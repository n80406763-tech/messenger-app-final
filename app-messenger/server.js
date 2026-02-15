/** @format */

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL } = require("url");

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, "public");
const DB_FILE = path.join(__dirname, "messenger.json");

const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const LOGIN_WINDOW_MS = 1000 * 60 * 5;
const LOGIN_LIMIT = 30;
const MESSAGE_WINDOW_MS = 1000 * 60;
const MESSAGE_LIMIT = 90;
const DEFAULT_MESSAGES_LIMIT = 40;
const MAX_MESSAGES_LIMIT = 100;
const MAX_ATTACHMENT_BYTES = 12 * 1024 * 1024;
const MAX_BODY_BYTES = 16 * 1024 * 1024;
const MAX_AVATAR_BYTES = 2 * 1024 * 1024;

const SUPPORT_TITLE = "Чат поддержки";
const SUPPORT_CATEGORIES = [
  "Проблема с аккаунтом",
  "Жалоба на пользователя",
  "Проблема с медиа",
  "Ошибка приложения",
  "Другое",
];

const DEFAULT_SUPPORT_ADMIN = {
  username: process.env.SUPPORT_ADMIN_USERNAME || "support",
  password: process.env.SUPPORT_ADMIN_PASSWORD || "support123",
};

const DEFAULT_SUPPORT_AGENT = {
  username: process.env.SUPPORT_AGENT_USERNAME || "helper",
  password: process.env.SUPPORT_AGENT_PASSWORD || "helper123",
};

const sessions = new Map();
const sseClients = new Map();
const ipLoginRequests = new Map();
const userMessageRequests = new Map();

function createInitialState() {
  return {
    users: [],
    conversations: [],
    messages: [],
    nextUserId: 1,
    nextConversationId: 1,
    nextMessageId: 1,
  };
}

function loadState() {
  if (!fs.existsSync(DB_FILE)) return createInitialState();
  try {
    const raw = fs.readFileSync(DB_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return {
      users: parsed.users || [],
      conversations: parsed.conversations || [],
      messages: parsed.messages || [],
      nextUserId: parsed.nextUserId || 1,
      nextConversationId: parsed.nextConversationId || 1,
      nextMessageId: parsed.nextMessageId || 1,
    };
  } catch {
    return createInitialState();
  }
}

let state = loadState();

function normalizeLegacyUsers() {
  state.users = state.users.map((u) => ({
    ...u,
    role: u.role || "user",
    avatar: u.avatar || null,
    hideName: Boolean(u.hideName),
    lastSeenAt: u.lastSeenAt || null,
    showOnlineStatus: u.showOnlineStatus !== false,
    allowAvatarView: u.allowAvatarView !== false,
    allowAvatarDownload: Boolean(u.allowAvatarDownload),
  }));
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto
    .pbkdf2Sync(password, salt, 120000, 64, "sha512")
    .toString("hex");
  return `${salt}:${hash}`;
}

function ensureSupportAdmin() {
  const exists = state.users.find((u) => u.role === "support_admin");
  if (exists) return;

  const supportAdmin = {
    id: state.nextUserId++,
    username: DEFAULT_SUPPORT_ADMIN.username,
    passwordHash: hashPassword(DEFAULT_SUPPORT_ADMIN.password),
    role: "support_admin",
    avatar: null,
    hideName: false,
    lastSeenAt: null,
    showOnlineStatus: true,
    allowAvatarView: true,
    allowAvatarDownload: false,
  };
  state.users.push(supportAdmin);
  saveState();
}

function ensureDefaultSupportAgent() {
  const exists = state.users.find((u) => u.role === "support_agent");
  if (exists) return;

  const supportAgent = {
    id: state.nextUserId++,
    username: DEFAULT_SUPPORT_AGENT.username,
    passwordHash: hashPassword(DEFAULT_SUPPORT_AGENT.password),
    role: "support_agent",
    avatar: null,
    hideName: false,
    lastSeenAt: null,
    showOnlineStatus: true,
    allowAvatarView: true,
    allowAvatarDownload: false,
  };
  state.users.push(supportAgent);
  saveState();
}

function saveState() {
  const tmp = `${DB_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

normalizeLegacyUsers();
ensureSupportAdmin();
ensureDefaultSupportAgent();

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > MAX_BODY_BYTES) {
        reject(new Error("Payload too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

function normalizeUsername(input) {
  return String(input || "").trim();
}

function normalizeText(input) {
  return String(input || "")
    .replace(/\r/g, "")
    .trim();
}

function isValidUsername(username) {
  return /^[a-zA-Zа-яА-Я0-9._-]{3,24}$/.test(username);
}

function consumeRateLimit(bucket, key, windowMs, limit) {
  const now = Date.now();
  const recent = (bucket.get(key) || []).filter((ts) => now - ts < windowMs);
  recent.push(now);
  bucket.set(key, recent);
  return recent.length <= limit;
}

function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0)
    return xff.split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
}

function verifyPassword(password, stored) {
  const [salt, expected] = String(stored).split(":");
  if (!salt || !expected) return false;
  const actual = crypto
    .pbkdf2Sync(password, salt, 120000, 64, "sha512")
    .toString("hex");
  return crypto.timingSafeEqual(
    Buffer.from(expected, "hex"),
    Buffer.from(actual, "hex")
  );
}

function createSession(user) {
  const token = crypto.randomBytes(24).toString("hex");
  sessions.set(token, { userId: user.id, touchedAt: Date.now() });
  return token;
}

function cleanExpiredSessions() {
  const now = Date.now();
  for (const [token, session] of sessions.entries()) {
    if (now - session.touchedAt > SESSION_TTL_MS) sessions.delete(token);
  }
}

function readAuth(req) {
  cleanExpiredSessions();
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token || !sessions.has(token)) return null;

  const session = sessions.get(token);
  session.touchedAt = Date.now();
  const user = state.users.find((u) => u.id === session.userId);
  if (!user) return null;
  return { token, user };
}

function isUserOnline(userId) {
  for (const meta of sseClients.values()) {
    if (meta.user.id === userId) return true;
  }
  return false;
}

function displayNameForViewer(user, viewerId) {
  if (user.hideName && user.id !== viewerId) return `user${user.id}`;
  return user.username;
}

function toPublicUser(user, viewerId) {
  const isSelf = user.id === viewerId;
  const canSeeOnline = isSelf || user.showOnlineStatus;
  const canSeeAvatar = isSelf || user.allowAvatarView;

  return {
    id: user.id,
    username: displayNameForViewer(user, viewerId),
    handle: user.username,
    avatar: canSeeAvatar ? user.avatar || null : null,
    canDownloadAvatar: canSeeAvatar
      ? isSelf || user.allowAvatarDownload
      : false,
    online: canSeeOnline ? isUserOnline(user.id) : false,
    lastSeenAt: canSeeOnline ? user.lastSeenAt || null : null,
    hideName: isSelf ? user.hideName : undefined,
    role: isSelf ? user.role : undefined,
    isSupport: isSupportRole(user),
    showOnlineStatus: isSelf ? user.showOnlineStatus : undefined,
    allowAvatarView: isSelf ? user.allowAvatarView : undefined,
    allowAvatarDownload: isSelf ? user.allowAvatarDownload : undefined,
  };
}

function getConversationById(conversationId) {
  return state.conversations.find((c) => c.id === conversationId) || null;
}

function isSupportRole(user) {
  return Boolean(
    user && (user.role === "support_admin" || user.role === "support_agent")
  );
}

function canReceiveConversation(conversation, user) {
  if (!user) return false;
  if (conversation.type === "support") {
    return conversation.participantIds.includes(user.id) || isSupportRole(user);
  }
  return conversation.participantIds.includes(user.id);
}

function listConversationsForUser(user) {
  return state.conversations.filter((conversation) =>
    canReceiveConversation(conversation, user)
  );
}

function canAccessConversation(conversation, userId) {
  const user = state.users.find((u) => u.id === userId);
  return canReceiveConversation(conversation, user);
}

function getOnlineSummaryForConversation(conversation) {
  const onlineIds = new Set();
  for (const meta of sseClients.values()) {
    if (canReceiveConversation(conversation, meta.user))
      onlineIds.add(meta.user.id);
  }
  return onlineIds.size;
}

function serializeMessageForViewer(message, viewerId) {
  const sender = state.users.find((u) => u.id === message.senderId);
  const viewer = state.users.find((u) => u.id === viewerId);
  const conversation = getConversationById(message.conversationId);
  const isSupportConversation = conversation?.type === "support";
  const hideSupportIdentity =
    isSupportConversation && !isSupportRole(viewer) && isSupportRole(sender);

  return {
    id: message.id,
    conversationId: message.conversationId,
    sender: hideSupportIdentity
      ? "Поддержка"
      : sender
        ? displayNameForViewer(sender, viewerId)
        : message.senderName || "Support",
    senderId: hideSupportIdentity ? 0 : message.senderId,
    text: message.text,
    attachment: message.attachment || null,
    createdAt: message.createdAt,
  };
}

function serializeConversation(conversation, requesterId) {
  const requester = state.users.find((u) => u.id === requesterId);
  const isSupportViewer = isSupportRole(requester);
  const participants = conversation.participantIds
    .map((id) => state.users.find((u) => u.id === id))
    .filter(Boolean)
    .map((u) => toPublicUser(u, requesterId));

  const last =
    [...state.messages]
      .reverse()
      .find((m) => m.conversationId === conversation.id) || null;
  const lastMessage = last
    ? serializeMessageForViewer(last, requesterId)
    : null;

  const title =
    conversation.type === "group"
      ? conversation.title
      : conversation.type === "support"
        ? isSupportViewer
          ? `Поддержка: ${participants[0]?.username || "пользователь"}`
          : SUPPORT_TITLE
        : participants.find((p) => p.id !== requesterId)?.username || "Диалог";

  return {
    id: conversation.id,
    type: conversation.type,
    title,
    participantIds: conversation.participantIds,
    participants,
    createdAt: conversation.createdAt,
    onlineCount: getOnlineSummaryForConversation(conversation),
    lastMessage,
  };
}

function broadcast(event, payloadBuilder, filterFn = null) {
  for (const [res, meta] of sseClients.entries()) {
    if (res.writableEnded) {
      sseClients.delete(res);
      continue;
    }
    if (filterFn && !filterFn(meta)) continue;

    const payload =
      typeof payloadBuilder === "function"
        ? payloadBuilder(meta)
        : payloadBuilder;
    const raw = `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
    res.write(raw);
  }
}

function broadcastConversationPresence(conversationId) {
  const conversation = getConversationById(conversationId);
  if (!conversation) return;
  broadcast(
    "presence",
    {
      conversationId,
      onlineCount: getOnlineSummaryForConversation(conversation),
    },
    (meta) => canReceiveConversation(conversation, meta.user)
  );
}

function broadcastConversationUpdated(conversationId) {
  const conversation = getConversationById(conversationId);
  if (!conversation) return;
  broadcast(
    "conversation_updated",
    (meta) => serializeConversation(conversation, meta.user.id),
    (meta) => canReceiveConversation(conversation, meta.user)
  );
}

function parseImageDataUrl(dataUrl, maxBytes) {
  if (typeof dataUrl !== "string") return null;
  const match = dataUrl.match(
    /^data:(image\/[a-zA-Z0-9.+-]+)(?:;[^,]*)?;base64,([A-Za-z0-9+/=]+)$/
  );
  if (!match) return null;
  const bytes = Buffer.from(match[2], "base64");
  if (bytes.length > maxBytes) return null;
  return dataUrl;
}

function parseAttachmentDataUrl(dataUrl) {
  if (typeof dataUrl !== "string") return null;
  const match = dataUrl.match(
    /^data:([^;,]+)(?:;[^,]*)?;base64,([A-Za-z0-9+/=]+)$/
  );
  if (!match) return null;

  const mime = match[1];
  const bytes = Buffer.from(match[2], "base64");
  if (bytes.length > MAX_ATTACHMENT_BYTES) return null;

  const type = mime.startsWith("image/")
    ? "image"
    : mime.startsWith("video/")
      ? "video"
      : null;
  if (!type) return null;

  return {
    type,
    mime,
    name: `${type}_${Date.now()}`,
    size: bytes.length,
    dataUrl,
  };
}

function readMessagesPage(conversationId, searchParams, viewerId) {
  const beforeId = Number(searchParams.get("before_id") || "0");
  const requestedLimit = Number(
    searchParams.get("limit") || String(DEFAULT_MESSAGES_LIMIT)
  );
  const limit = Number.isFinite(requestedLimit)
    ? Math.max(1, Math.min(MAX_MESSAGES_LIMIT, Math.floor(requestedLimit)))
    : DEFAULT_MESSAGES_LIMIT;

  let source = state.messages.filter(
    (m) => m.conversationId === conversationId
  );
  if (beforeId > 0) source = source.filter((m) => m.id < beforeId);

  const page = source
    .slice(-limit)
    .map((m) => serializeMessageForViewer(m, viewerId));
  const hasMore = source.length > page.length;
  return { messages: page, hasMore };
}

function getOrCreateSupportConversation(userId) {
  const existing = state.conversations.find(
    (c) =>
      c.type === "support" &&
      c.participantIds.length === 1 &&
      c.participantIds[0] === userId
  );
  if (existing) return existing;

  const conversation = {
    id: state.nextConversationId++,
    type: "support",
    title: SUPPORT_TITLE,
    participantIds: [userId],
    createdAt: new Date().toISOString(),
  };

  state.conversations.push(conversation);
  saveState();
  return conversation;
}

function buildSupportReply(category) {
  const text = category
    ? `Спасибо, мы приняли обращение: "${category}". Оператор проверит и ответит в этом чате.`
    : "Здравствуйте! Опишите проблему подробно. Мы поможем.";

  return {
    id: state.nextMessageId++,
    conversationId: 0,
    senderId: 0,
    senderName: "Support",
    text,
    attachment: null,
    createdAt: new Date().toISOString(),
  };
}

function serveStatic(req, res, pathname) {
  const rel = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const filePath = path.resolve(PUBLIC_DIR, rel);
  if (!filePath.startsWith(PUBLIC_DIR))
    return sendJson(res, 403, { error: "Forbidden" });

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end("Not Found");
      return;
    }

    const ext = path.extname(filePath);
    const type =
      ext === ".html"
        ? "text/html; charset=utf-8"
        : ext === ".css"
          ? "text/css; charset=utf-8"
          : ext === ".js"
            ? "application/javascript; charset=utf-8"
            : "application/octet-stream";

    res.writeHead(200, {
      "Content-Type": type,
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy":
        "default-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'",
    });
    res.end(data);
  });
}

async function handleApi(req, res, pathname, searchParams = null) {
  const params =
    searchParams ||
    new URL(req.url, `http://${req.headers.host || "localhost"}`).searchParams;

  if (req.method === "GET" && pathname === "/api/health") {
    return sendJson(res, 200, {
      ok: true,
      users: state.users.length,
      conversations: state.conversations.length,
      messages: state.messages.length,
    });
  }

  if (req.method === "POST" && pathname === "/api/register") {
    try {
      const body = await parseBody(req);
      const username = normalizeUsername(body.username);
      const password = String(body.password || "");

      if (!isValidUsername(username) || password.length < 6) {
        return sendJson(res, 400, {
          error: "Username 3-24 chars and password min 6 chars required.",
        });
      }

      const exists = state.users.find(
        (u) => u.username.toLowerCase() === username.toLowerCase()
      );
      if (exists)
        return sendJson(res, 409, { error: "Username already exists" });

      const user = {
        id: state.nextUserId++,
        username,
        passwordHash: hashPassword(password),
        role: "user",
        avatar: null,
        hideName: false,
        lastSeenAt: null,
        showOnlineStatus: true,
        allowAvatarView: true,
        allowAvatarDownload: false,
      };
      state.users.push(user);
      saveState();
      return sendJson(res, 201, { user: toPublicUser(user, user.id) });
    } catch (error) {
      return sendJson(res, 400, { error: error.message });
    }
  }

  if (req.method === "POST" && pathname === "/api/login") {
    try {
      const ip = getClientIp(req);
      if (
        !consumeRateLimit(ipLoginRequests, ip, LOGIN_WINDOW_MS, LOGIN_LIMIT)
      ) {
        return sendJson(res, 429, {
          error: "Too many login attempts. Try again later.",
        });
      }

      const body = await parseBody(req);
      const username = normalizeUsername(body.username);
      const password = String(body.password || "");
      const user = state.users.find(
        (u) => u.username.toLowerCase() === username.toLowerCase()
      );
      if (!user || !verifyPassword(password, user.passwordHash)) {
        return sendJson(res, 401, { error: "Invalid credentials" });
      }

      user.lastSeenAt = new Date().toISOString();
      saveState();
      const token = createSession(user);
      return sendJson(res, 200, { token, user: toPublicUser(user, user.id) });
    } catch (error) {
      return sendJson(res, 400, { error: error.message });
    }
  }

  if (req.method === "POST" && pathname === "/api/logout") {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });
    sessions.delete(auth.token);
    return sendJson(res, 200, { ok: true });
  }

  if (req.method === "GET" && pathname === "/api/me") {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });
    return sendJson(res, 200, { user: toPublicUser(auth.user, auth.user.id) });
  }

  if (req.method === "GET" && pathname === "/api/profile") {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });
    return sendJson(res, 200, {
      username: auth.user.username,
      avatar: auth.user.avatar,
      hideName: auth.user.hideName,
      role: auth.user.role,
      showOnlineStatus: auth.user.showOnlineStatus,
      allowAvatarView: auth.user.allowAvatarView,
      allowAvatarDownload: auth.user.allowAvatarDownload,
    });
  }

  if (req.method === "POST" && pathname === "/api/profile") {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });

    try {
      const body = await parseBody(req);
      const hideName =
        typeof body.hideName === "boolean" ? body.hideName : auth.user.hideName;
      const showOnlineStatus =
        typeof body.showOnlineStatus === "boolean"
          ? body.showOnlineStatus
          : auth.user.showOnlineStatus;
      const allowAvatarView =
        typeof body.allowAvatarView === "boolean"
          ? body.allowAvatarView
          : auth.user.allowAvatarView;
      const allowAvatarDownload =
        typeof body.allowAvatarDownload === "boolean"
          ? body.allowAvatarDownload
          : auth.user.allowAvatarDownload;
      let avatar = auth.user.avatar;

      if (body.avatarDataUrl === null) avatar = null;
      if (typeof body.avatarDataUrl === "string") {
        const parsedAvatar = parseImageDataUrl(
          body.avatarDataUrl,
          MAX_AVATAR_BYTES
        );
        if (!parsedAvatar)
          return sendJson(res, 400, {
            error: "Invalid avatar image (max 2MB)",
          });
        avatar = parsedAvatar;
      }

      auth.user.hideName = hideName;
      auth.user.showOnlineStatus = showOnlineStatus;
      auth.user.allowAvatarView = allowAvatarView;
      auth.user.allowAvatarDownload = allowAvatarDownload;
      auth.user.avatar = avatar;
      saveState();

      return sendJson(res, 200, {
        user: toPublicUser(auth.user, auth.user.id),
      });
    } catch (error) {
      return sendJson(res, 400, { error: error.message });
    }
  }

  if (req.method === "GET" && pathname === "/api/support/agents") {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });
    if (auth.user.role !== "support_admin")
      return sendJson(res, 403, { error: "Forbidden" });

    const agents = state.users
      .filter((u) => u.role === "support_admin" || u.role === "support_agent")
      .map((u) => ({ ...toPublicUser(u, auth.user.id), role: u.role }));
    return sendJson(res, 200, { agents });
  }

  if (req.method === "POST" && pathname === "/api/support/agents") {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });
    if (auth.user.role !== "support_admin")
      return sendJson(res, 403, { error: "Forbidden" });

    try {
      const body = await parseBody(req);
      const username = normalizeUsername(body.username);
      const password = String(body.password || "");

      if (!isValidUsername(username) || password.length < 6) {
        return sendJson(res, 400, {
          error: "Username 3-24 chars and password min 6 chars required.",
        });
      }

      const exists = state.users.find(
        (u) => u.username.toLowerCase() === username.toLowerCase()
      );
      if (exists)
        return sendJson(res, 409, { error: "Username already exists" });

      const user = {
        id: state.nextUserId++,
        username,
        passwordHash: hashPassword(password),
        role: "support_agent",
        avatar: null,
        hideName: false,
        lastSeenAt: null,
        showOnlineStatus: true,
        allowAvatarView: true,
        allowAvatarDownload: false,
      };
      state.users.push(user);
      saveState();
      return sendJson(res, 201, { user: toPublicUser(user, auth.user.id) });
    } catch (error) {
      return sendJson(res, 400, { error: error.message });
    }
  }

  if (req.method === "GET" && pathname === "/api/support/categories") {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });
    return sendJson(res, 200, { categories: SUPPORT_CATEGORIES });
  }

  if (req.method === "GET" && pathname === "/api/users/search") {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });

    const q = normalizeUsername(params.get("q") || "").toLowerCase();
    const users = state.users
      .filter((u) => u.id !== auth.user.id)
      .filter((u) => (isSupportRole(auth.user) ? true : !isSupportRole(u)))
      .filter((u) => (q ? u.username.toLowerCase().includes(q) : true))
      .slice(0, 20)
      .map((u) => toPublicUser(u, auth.user.id));

    return sendJson(res, 200, { users });
  }

  const userStatusMatch = pathname.match(/^\/api\/users\/(\d+)\/status$/);
  if (req.method === "GET" && userStatusMatch) {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });

    const userId = Number(userStatusMatch[1]);
    const user = state.users.find((u) => u.id === userId);
    if (!user) return sendJson(res, 404, { error: "User not found" });

    const canSeeOnline = user.id === auth.user.id || user.showOnlineStatus;
    return sendJson(res, 200, {
      userId: user.id,
      online: canSeeOnline ? isUserOnline(user.id) : false,
      lastSeenAt: canSeeOnline ? user.lastSeenAt || null : null,
    });
  }

  const avatarMatch = pathname.match(/^\/api\/users\/(\d+)\/avatar$/);
  if (req.method === "GET" && avatarMatch) {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });

    const userId = Number(avatarMatch[1]);
    const user = state.users.find((u) => u.id === userId);
    if (!user) return sendJson(res, 404, { error: "User not found" });

    const canSeeAvatar = user.id === auth.user.id || user.allowAvatarView;
    const canDownload = user.id === auth.user.id || user.allowAvatarDownload;
    if (!canSeeAvatar || !canDownload || !user.avatar) {
      return sendJson(res, 403, { error: "Avatar download not allowed" });
    }

    return sendJson(res, 200, { avatarDataUrl: user.avatar });
  }
  if (req.method === "GET" && pathname === "/api/conversations") {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });

    const list = state.conversations
      .filter((c) => canReceiveConversation(c, auth.user))
      .map((c) => serializeConversation(c, auth.user.id))
      .sort((a, b) => (b.lastMessage?.id || 0) - (a.lastMessage?.id || 0));

    return sendJson(res, 200, { conversations: list });
  }

  if (req.method === "POST" && pathname === "/api/conversations/direct") {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });

    try {
      const body = await parseBody(req);
      const targetUserId = Number(body.targetUserId || 0);
      const target = state.users.find((u) => u.id === targetUserId);
      if (!target || target.id === auth.user.id)
        return sendJson(res, 400, { error: "Invalid target user" });
      if (isSupportRole(auth.user) || isSupportRole(target)) {
        return sendJson(res, 403, {
          error: "Написать поддержке можно только через чат поддержки",
        });
      }

      const existing = state.conversations.find(
        (c) =>
          c.type === "direct" &&
          c.participantIds.length === 2 &&
          c.participantIds.includes(auth.user.id) &&
          c.participantIds.includes(target.id)
      );
      if (existing)
        return sendJson(res, 200, {
          conversation: serializeConversation(existing, auth.user.id),
        });

      const conversation = {
        id: state.nextConversationId++,
        type: "direct",
        title: null,
        participantIds: [auth.user.id, target.id],
        createdAt: new Date().toISOString(),
      };
      state.conversations.push(conversation);
      saveState();
      return sendJson(res, 201, {
        conversation: serializeConversation(conversation, auth.user.id),
      });
    } catch (error) {
      return sendJson(res, 400, { error: error.message });
    }
  }

  if (req.method === "POST" && pathname === "/api/conversations/group") {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });

    try {
      const body = await parseBody(req);
      const title = normalizeText(body.title);
      const rawMembers = Array.isArray(body.memberIds) ? body.memberIds : [];
      const memberIds = [
        ...new Set(
          rawMembers.map((id) => Number(id)).filter((id) => Number.isFinite(id))
        ),
      ];
      const participants = [...new Set([auth.user.id, ...memberIds])].filter(
        (id) => state.users.some((u) => u.id === id)
      );

      if (title.length < 2 || participants.length < 3) {
        return sendJson(res, 400, {
          error: "Group title too short or too few participants",
        });
      }

      const conversation = {
        id: state.nextConversationId++,
        type: "group",
        title,
        participantIds: participants,
        createdAt: new Date().toISOString(),
      };

      state.conversations.push(conversation);
      saveState();
      return sendJson(res, 201, {
        conversation: serializeConversation(conversation, auth.user.id),
      });
    } catch (error) {
      return sendJson(res, 400, { error: error.message });
    }
  }

  if (req.method === "POST" && pathname === "/api/conversations/support") {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });
    if (isSupportRole(auth.user)) {
      return sendJson(res, 400, {
        error: "Сотрудники поддержки отвечают в уже созданных чатах",
      });
    }

    const conversation = getOrCreateSupportConversation(auth.user.id);
    const hasMessages = state.messages.some(
      (m) => m.conversationId === conversation.id
    );
    if (!hasMessages) {
      const firstReply = buildSupportReply();
      firstReply.conversationId = conversation.id;
      state.messages.push(firstReply);
      saveState();
    }

    broadcastConversationUpdated(conversation.id);

    return sendJson(res, 200, {
      conversation: serializeConversation(conversation, auth.user.id),
    });
  }

  if (
    req.method === "POST" &&
    pathname.startsWith("/api/conversations/") &&
    pathname.endsWith("/rename")
  ) {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });

    try {
      const conversationId = Number(pathname.split("/")[3]);
      const conversation = getConversationById(conversationId);
      if (!conversation || !canAccessConversation(conversation, auth.user.id)) {
        return sendJson(res, 404, { error: "Conversation not found" });
      }
      if (conversation.type !== "group")
        return sendJson(res, 400, { error: "Only group can be renamed" });

      const body = await parseBody(req);
      const title = normalizeText(body.title);
      if (title.length < 2)
        return sendJson(res, 400, { error: "Group title too short" });

      conversation.title = title;
      saveState();
      broadcastConversationUpdated(conversation.id);
      return sendJson(res, 200, {
        conversation: serializeConversation(conversation, auth.user.id),
      });
    } catch (error) {
      return sendJson(res, 400, { error: error.message });
    }
  }

  if (
    req.method === "POST" &&
    pathname.startsWith("/api/conversations/") &&
    pathname.endsWith("/members/add")
  ) {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });

    try {
      const conversationId = Number(pathname.split("/")[3]);
      const conversation = getConversationById(conversationId);
      if (!conversation || !canAccessConversation(conversation, auth.user.id)) {
        return sendJson(res, 404, { error: "Conversation not found" });
      }
      if (conversation.type !== "group") {
        return sendJson(res, 400, {
          error: "Only group members can be changed",
        });
      }

      const body = await parseBody(req);
      const memberIds = Array.isArray(body.memberIds) ? body.memberIds : [];
      const validIds = [
        ...new Set(
          memberIds.map((id) => Number(id)).filter((id) => Number.isFinite(id))
        ),
      ].filter((id) => state.users.some((u) => u.id === id));

      conversation.participantIds = [
        ...new Set([...conversation.participantIds, ...validIds]),
      ];
      saveState();
      broadcastConversationUpdated(conversation.id);
      return sendJson(res, 200, {
        conversation: serializeConversation(conversation, auth.user.id),
      });
    } catch (error) {
      return sendJson(res, 400, { error: error.message });
    }
  }

  if (
    req.method === "POST" &&
    pathname.startsWith("/api/conversations/") &&
    pathname.endsWith("/members/remove")
  ) {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });

    try {
      const conversationId = Number(pathname.split("/")[3]);
      const conversation = getConversationById(conversationId);
      if (!conversation || !canAccessConversation(conversation, auth.user.id)) {
        return sendJson(res, 404, { error: "Conversation not found" });
      }
      if (conversation.type !== "group") {
        return sendJson(res, 400, {
          error: "Only group members can be changed",
        });
      }

      const body = await parseBody(req);
      const memberId = Number(body.memberId || 0);
      if (!memberId || memberId === auth.user.id)
        return sendJson(res, 400, { error: "Cannot remove this member" });

      conversation.participantIds = conversation.participantIds.filter(
        (id) => id !== memberId
      );
      if (conversation.participantIds.length < 2) {
        return sendJson(res, 400, {
          error: "Group must keep at least 2 members",
        });
      }

      saveState();
      broadcastConversationUpdated(conversation.id);
      return sendJson(res, 200, {
        conversation: serializeConversation(conversation, auth.user.id),
      });
    } catch (error) {
      return sendJson(res, 400, { error: error.message });
    }
  }

  if (
    req.method === "GET" &&
    pathname.startsWith("/api/conversations/") &&
    pathname.endsWith("/messages")
  ) {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });

    const conversationId = Number(pathname.split("/")[3]);
    const conversation = getConversationById(conversationId);
    if (!conversation || !canAccessConversation(conversation, auth.user.id)) {
      return sendJson(res, 404, { error: "Conversation not found" });
    }

    return sendJson(
      res,
      200,
      readMessagesPage(conversationId, params, auth.user.id)
    );
  }

  if (
    req.method === "POST" &&
    pathname.startsWith("/api/conversations/") &&
    pathname.endsWith("/messages")
  ) {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });

    const conversationId = Number(pathname.split("/")[3]);
    const conversation = getConversationById(conversationId);
    if (!conversation || !canAccessConversation(conversation, auth.user.id)) {
      return sendJson(res, 404, { error: "Conversation not found" });
    }

    if (
      !consumeRateLimit(
        userMessageRequests,
        String(auth.user.id),
        MESSAGE_WINDOW_MS,
        MESSAGE_LIMIT
      )
    ) {
      return sendJson(res, 429, {
        error: "Rate limit exceeded (max 90 messages/min)",
      });
    }

    try {
      const body = await parseBody(req);
      const text = normalizeText(body.text);
      const attachment = body.attachment
        ? parseAttachmentDataUrl(body.attachment.dataUrl)
        : null;

      const complaintType = normalizeText(body.complaintType || "");
      const isSupportComplaint =
        conversation.type === "support" &&
        SUPPORT_CATEGORIES.some((c) => c === complaintType);

      if (!text && !attachment && !isSupportComplaint) {
        return sendJson(res, 400, { error: "Message text or media required" });
      }
      if (text.length > 1200)
        return sendJson(res, 400, { error: "Text too long (max 1200)" });
      if (body.attachment && !attachment) {
        return sendJson(res, 400, {
          error: "Invalid media. Allowed: image/* or video/* up to 12MB.",
        });
      }

      const message = {
        id: state.nextMessageId++,
        conversationId,
        senderId: auth.user.id,
        text: text || (isSupportComplaint ? `Жалоба: ${complaintType}` : ""),
        attachment,
        createdAt: new Date().toISOString(),
      };

      state.messages.push(message);
      if (state.messages.length > 5000)
        state.messages = state.messages.slice(-5000);
      saveState();

      broadcast(
        "message",
        (meta) => serializeMessageForViewer(message, meta.user.id),
        (meta) => canReceiveConversation(conversation, meta.user)
      );

      if (
        conversation.type === "support" &&
        isSupportComplaint &&
        !isSupportRole(auth.user)
      ) {
        const info = buildSupportReply(complaintType);
        info.conversationId = conversation.id;
        state.messages.push(info);
        saveState();
        broadcast(
          "message",
          (meta) => serializeMessageForViewer(info, meta.user.id),
          (meta) => canReceiveConversation(conversation, meta.user)
        );
      }

      return sendJson(res, 201, {
        message: serializeMessageForViewer(message, auth.user.id),
      });
    } catch (error) {
      return sendJson(res, 400, { error: error.message });
    }
  }

  if (req.method === "GET" && pathname === "/api/events") {
    const auth = readAuth(req);
    if (!auth) return sendJson(res, 401, { error: "Unauthorized" });

    res.writeHead(200, {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
    });

    const heartbeat = setInterval(() => {
      if (!res.writableEnded) res.write("event: ping\ndata: {}\n\n");
    }, 15000);

    sseClients.set(res, { user: auth.user });
    auth.user.lastSeenAt = new Date().toISOString();
    saveState();

    res.write(
      `event: ready\ndata: ${JSON.stringify({ user: toPublicUser(auth.user, auth.user.id) })}\n\n`
    );

    const conversations = listConversationsForUser(auth.user);
    conversations.forEach((c) => broadcastConversationPresence(c.id));

    req.on("close", () => {
      clearInterval(heartbeat);
      sseClients.delete(res);
      auth.user.lastSeenAt = new Date().toISOString();
      saveState();
      conversations.forEach((c) => broadcastConversationPresence(c.id));
    });
    return;
  }

  return sendJson(res, 404, { error: "Not found" });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  if (url.pathname.startsWith("/api/")) {
    await handleApi(req, res, url.pathname, url.searchParams);
    return;
  }
  serveStatic(req, res, url.pathname);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Messenger running on ${PORT}`);
});
