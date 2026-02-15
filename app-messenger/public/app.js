/** @format */

const authPanel = document.getElementById("authPanel");
const chatPanel = document.getElementById("chatPanel");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const authMessage = document.getElementById("authMessage");
const chatMessage = document.getElementById("chatMessage");
const loginBtn = document.getElementById("loginBtn");
const registerBtn = document.getElementById("registerBtn");
const openSettingsBtn = document.getElementById("openSettingsBtn");
const logoutBtn = document.getElementById("logoutBtn");
const conversationSearchInput = document.getElementById(
  "conversationSearchInput"
);
const userSearchInput = document.getElementById("userSearchInput");
const userSearchResults = document.getElementById("userSearchResults");
const openCreateGroupBtn = document.getElementById("openCreateGroupBtn");
const openGroupSettingsBtn = document.getElementById("openGroupSettingsBtn");
const supportChatBtn = document.getElementById("supportChatBtn");
const conversationsList = document.getElementById("conversationsList");
const dialogTitle = document.getElementById("dialogTitle");
const dialogMeta = document.getElementById("dialogMeta");
const supportActions = document.getElementById("supportActions");
const connBadge = document.getElementById("connBadge");
const loadOlderBtn = document.getElementById("loadOlderBtn");
const messagesEl = document.getElementById("messages");
const messageForm = document.getElementById("messageForm");
const messageInput = document.getElementById("messageInput");
const mediaInput = document.getElementById("mediaInput");
const mediaPreview = document.getElementById("mediaPreview");
const meLabel = document.getElementById("meLabel");

const groupModal = document.getElementById("groupModal");
const groupModalTitle = document.getElementById("groupModalTitle");
const groupTitleInput = document.getElementById("groupTitleInput");
const groupMemberSearchInput = document.getElementById(
  "groupMemberSearchInput"
);
const groupMemberCandidates = document.getElementById("groupMemberCandidates");
const selectedGroupMembers = document.getElementById("selectedGroupMembers");
const saveGroupBtn = document.getElementById("saveGroupBtn");
const cancelGroupBtn = document.getElementById("cancelGroupBtn");

const settingsModal = document.getElementById("settingsModal");
const avatarInput = document.getElementById("avatarInput");
const avatarPreview = document.getElementById("avatarPreview");
const hideNameCheckbox = document.getElementById("hideNameCheckbox");
const showOnlineStatusCheckbox = document.getElementById(
  "showOnlineStatusCheckbox"
);
const allowAvatarViewCheckbox = document.getElementById(
  "allowAvatarViewCheckbox"
);
const allowAvatarDownloadCheckbox = document.getElementById(
  "allowAvatarDownloadCheckbox"
);
const supportAdminPanel = document.getElementById("supportAdminPanel");
const supportAgentUsername = document.getElementById("supportAgentUsername");
const supportAgentPassword = document.getElementById("supportAgentPassword");
const createSupportAgentBtn = document.getElementById("createSupportAgentBtn");
const supportAgentsList = document.getElementById("supportAgentsList");
const saveSettingsBtn = document.getElementById("saveSettingsBtn");
const cancelSettingsBtn = document.getElementById("cancelSettingsBtn");
const togglePushBtn = document.getElementById("togglePushBtn");
const pushStatus = document.getElementById("pushStatus");

let token = localStorage.getItem("messenger_token") || "";
let currentUser = null;
let conversations = [];
let activeConversation = null;
let hasOlder = false;
let streamAbortController = null;
let reconnectTimer = null;
let allUsersCache = [];
let selectedGroupMemberIds = new Set();
let supportCategories = [];
let groupModalMode = "create";
let selectedAvatarDataUrl = undefined;

function setAuthMessage(text, isError = false) {
  authMessage.textContent = text;
  authMessage.style.color = isError ? "#b91c1c" : "#6b7280";
}

function setChatMessage(text, isError = false) {
  chatMessage.textContent = text;
  chatMessage.style.color = isError ? "#b91c1c" : "#6b7280";
}

function setConnectionState(online) {
  connBadge.textContent = online ? "online" : "offline";
  connBadge.style.background = online ? "#dcfce7" : "#e5e7eb";
}

async function api(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, { ...options, headers });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

function clearRealtime() {
  if (reconnectTimer) clearTimeout(reconnectTimer);
  reconnectTimer = null;
  if (streamAbortController) streamAbortController.abort();
  streamAbortController = null;
}

function avatarNode(user, size = 28) {
  if (user.avatar) {
    const img = document.createElement("img");
    img.className = "avatar";
    img.style.width = `${size}px`;
    img.style.height = `${size}px`;
    img.src = user.avatar;
    return img;
  }
  const div = document.createElement("div");
  div.className = "avatar";
  div.style.width = `${size}px`;
  div.style.height = `${size}px`;
  div.textContent = (user.username || "?").slice(0, 1).toUpperCase();
  return div;
}

function filteredConversations() {
  const q = conversationSearchInput.value.trim().toLowerCase();
  return conversations.filter((c) =>
    q ? c.title.toLowerCase().includes(q) : true
  );
}

function renderConversationList() {
  conversationsList.innerHTML = "";

  filteredConversations().forEach((conv) => {
    const el = document.createElement("div");
    el.className = "conv-item";
    if (activeConversation && activeConversation.id === conv.id)
      el.classList.add("active");

    const header = document.createElement("div");
    header.style.display = "flex";
    header.style.justifyContent = "space-between";
    header.innerHTML = `<strong>${conv.title}</strong><span class="muted">${conv.onlineCount || 0} online</span>`;

    const last = document.createElement("div");
    last.className = "muted";
    last.textContent =
      conv.lastMessage?.text || (conv.lastMessage?.attachment ? "Медиа" : "");

    el.append(header, last);
    el.addEventListener("click", () => openConversation(conv.id));
    conversationsList.appendChild(el);
  });
}

function messageNode(message) {
  const box = document.createElement("div");
  box.className = "msg";
  box.dataset.id = String(message.id);
  if (currentUser && message.senderId === currentUser.id)
    box.classList.add("my");

  const meta = document.createElement("div");
  meta.className = "meta";
  meta.textContent = `${message.sender} • ${new Date(message.createdAt).toLocaleString()}`;
  box.appendChild(meta);

  if (message.text) {
    const text = document.createElement("div");
    text.textContent = message.text;
    box.appendChild(text);
  }

  if (message.attachment) {
    if (message.attachment.type === "image") {
      const img = document.createElement("img");
      img.src = message.attachment.dataUrl;
      box.appendChild(img);
    }
    if (message.attachment.type === "video") {
      const video = document.createElement("video");
      video.src = message.attachment.dataUrl;
      video.controls = true;
      box.appendChild(video);
    }
  }

  return box;
}

function appendMessage(message, scroll = true) {
  messagesEl.appendChild(messageNode(message));
  if (scroll) messagesEl.scrollTop = messagesEl.scrollHeight;
}

function prependMessages(messages) {
  if (!messages.length) return;
  const before = messagesEl.scrollHeight;
  messages.forEach((m) =>
    messagesEl.insertBefore(messageNode(m), messagesEl.firstChild)
  );
  messagesEl.scrollTop += messagesEl.scrollHeight - before;
}

function activeFirstId() {
  const first = messagesEl.querySelector(".msg");
  return first ? Number(first.dataset.id || "0") : 0;
}

function renderSupportActions(show) {
  supportActions.innerHTML = "";
  supportActions.classList.toggle("hidden", !show);
  if (!show) return;

  supportCategories.forEach((category) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = category;
    btn.addEventListener("click", () => {
      sendSupportComplaint(category).catch((e) =>
        setChatMessage(e.message, true)
      );
    });
    supportActions.appendChild(btn);
  });
}

function setDialogMeta(conv) {
  dialogMeta.textContent =
    conv.type === "group"
      ? `Группа • онлайн ${conv.onlineCount} • участников ${conv.participantIds.length}`
      : conv.type === "support"
        ? "Поддержка • выберите категорию обращения ниже"
        : "Личный чат";

  openGroupSettingsBtn.classList.toggle("hidden", conv.type !== "group");
  renderSupportActions(conv.type === "support");
}

async function loadConversations() {
  const data = await api("/api/conversations");
  conversations = data.conversations || [];
  renderConversationList();
}

async function openConversation(conversationId) {
  const conv = conversations.find((c) => c.id === conversationId);
  if (!conv) return;
  activeConversation = conv;
  renderConversationList();

  dialogTitle.textContent = conv.title;
  setDialogMeta(conv);

  const data = await api(`/api/conversations/${conv.id}/messages?limit=30`);
  messagesEl.innerHTML = "";
  (data.messages || []).forEach((m) => appendMessage(m));

  hasOlder = Boolean(data.hasMore);
  loadOlderBtn.classList.toggle("hidden", !hasOlder);
}

async function loadOlderMessages() {
  if (!activeConversation || !hasOlder) return;
  const firstId = activeFirstId();
  if (!firstId) return;

  loadOlderBtn.textContent = "Загрузка...";
  loadOlderBtn.disabled = true;
  try {
    const data = await api(
      `/api/conversations/${activeConversation.id}/messages?limit=30&before_id=${firstId}`
    );
    prependMessages(data.messages || []);
    hasOlder = Boolean(data.hasMore);
    loadOlderBtn.classList.toggle("hidden", !hasOlder);
  } finally {
    loadOlderBtn.textContent = "Загрузить старые сообщения";
    loadOlderBtn.disabled = false;
  }
}

async function connectRealtime() {
  clearRealtime();
  streamAbortController = new AbortController();

  try {
    const res = await fetch("/api/events", {
      headers: { Authorization: `Bearer ${token}` },
      signal: streamAbortController.signal,
    });
    if (!res.ok || !res.body) throw new Error("Realtime failed");

    setConnectionState(true);
    const reader = res.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buffer = "";

    while (true) {
      const { value, done } = await reader.read();
      if (done) throw new Error("Stream closed");

      buffer += decoder.decode(value, { stream: true });
      const chunks = buffer.split("\n\n");
      buffer = chunks.pop() || "";

      for (const chunk of chunks) {
        const eventLine = chunk
          .split("\n")
          .find((l) => l.startsWith("event: "));
        const dataLine = chunk.split("\n").find((l) => l.startsWith("data: "));
        if (!eventLine || !dataLine) continue;

        const event = eventLine.replace("event: ", "");
        const payload = JSON.parse(dataLine.replace("data: ", ""));

        if (event === "message") {
          if (
            activeConversation &&
            payload.conversationId === activeConversation.id
          )
            appendMessage(payload);
          await loadConversations();
        }

        if (event === "presence") {
          conversations = conversations.map((c) =>
            c.id === payload.conversationId
              ? { ...c, onlineCount: payload.onlineCount }
              : c
          );
          renderConversationList();
          if (
            activeConversation &&
            activeConversation.id === payload.conversationId
          ) {
            activeConversation =
              conversations.find((c) => c.id === payload.conversationId) ||
              activeConversation;
            setDialogMeta(activeConversation);
          }
        }

        if (event === "conversation_updated") {
          const idx = conversations.findIndex((c) => c.id === payload.id);
          if (idx >= 0) conversations[idx] = payload;
          else conversations.unshift(payload);
          renderConversationList();

          if (activeConversation && activeConversation.id === payload.id) {
            activeConversation = payload;
            dialogTitle.textContent = payload.title;
            setDialogMeta(payload);
          }
        }
      }
    }
  } catch {
    if (!token) return;
    setConnectionState(false);
    reconnectTimer = setTimeout(() => connectRealtime().catch(() => {}), 1500);
  }
}

async function openDirectWithUser(user) {
  const data = await api("/api/conversations/direct", {
    method: "POST",
    body: JSON.stringify({ targetUserId: user.id }),
  });
  await loadConversations();
  await openConversation(data.conversation.id);
}

function renderSearchResults(users) {
  userSearchResults.innerHTML = "";
  users.forEach((u) => {
    const el = document.createElement("div");
    el.className = "search-item";

    const left = document.createElement("div");
    left.style.display = "flex";
    left.style.gap = "8px";
    left.style.alignItems = "center";
    left.appendChild(avatarNode(u));

    const info = document.createElement("div");
    const name = document.createElement("div");
    name.textContent = u.username;
    const st = document.createElement("div");
    st.className = "muted";
    st.textContent = u.online
      ? "online"
      : `last seen: ${u.lastSeenAt ? new Date(u.lastSeenAt).toLocaleString() : "unknown"}`;
    info.append(name, st);
    left.append(info);

    const action = document.createElement("button");
    action.className = "secondary";
    const blockedForDirect = Boolean(u.isSupport);
    action.textContent = blockedForDirect
      ? "Только через чат поддержки"
      : "Написать";
    action.disabled = blockedForDirect;
    if (!blockedForDirect) {
      action.addEventListener("click", () =>
        openDirectWithUser(u).catch((e) => setChatMessage(e.message, true))
      );
    }

    el.append(left, action);
    userSearchResults.appendChild(el);
  });
}

function renderSelectedGroupMembers() {
  selectedGroupMembers.innerHTML = "";
  const users = allUsersCache.filter((u) => selectedGroupMemberIds.has(u.id));
  users.forEach((u) => {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.textContent = u.username;

    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "×";
    remove.addEventListener("click", () => {
      selectedGroupMemberIds.delete(u.id);
      renderSelectedGroupMembers();
      renderGroupCandidates();
    });

    chip.appendChild(remove);
    selectedGroupMembers.appendChild(chip);
  });
}

function renderGroupCandidates() {
  const q = groupMemberSearchInput.value.trim().toLowerCase();
  groupMemberCandidates.innerHTML = "";

  if (q.length < 2) {
    const hint = document.createElement("div");
    hint.className = "muted";
    hint.textContent = "Введите минимум 2 символа для поиска участников";
    groupMemberCandidates.appendChild(hint);
    return;
  }

  const users = allUsersCache
    .filter((u) => !selectedGroupMemberIds.has(u.id))
    .filter((u) => u.username.toLowerCase().includes(q))
    .slice(0, 10);

  users.forEach((u) => {
    const el = document.createElement("div");
    el.className = "search-item";

    const name = document.createElement("span");
    name.textContent = u.username;

    const add = document.createElement("button");
    add.type = "button";
    add.textContent = "Добавить";
    add.addEventListener("click", () => {
      selectedGroupMemberIds.add(u.id);
      renderSelectedGroupMembers();
      renderGroupCandidates();
    });

    el.append(name, add);
    groupMemberCandidates.appendChild(el);
  });
}

async function refreshUsersCache() {
  const data = await api("/api/users/search?q=");
  allUsersCache = data.users || [];
}

async function searchUsers() {
  const q = userSearchInput.value.trim();
  const data = await api(`/api/users/search?q=${encodeURIComponent(q)}`);
  renderSearchResults(data.users || []);
}

function openGroupModal(mode) {
  groupModalMode = mode;
  groupModalTitle.textContent =
    mode === "create" ? "Создать группу" : "Настройки группы";

  if (mode === "edit" && activeConversation?.type === "group") {
    groupTitleInput.value = activeConversation.title;
    selectedGroupMemberIds = new Set(
      activeConversation.participantIds.filter((id) => id !== currentUser.id)
    );
  } else {
    groupTitleInput.value = "";
    selectedGroupMemberIds = new Set();
  }

  groupMemberSearchInput.value = "";
  renderSelectedGroupMembers();
  renderGroupCandidates();
  groupModal.classList.remove("hidden");
}

function closeGroupModal() {
  groupModal.classList.add("hidden");
}

async function saveGroupFromModal() {
  const title = groupTitleInput.value.trim();
  const memberIds = Array.from(selectedGroupMemberIds);

  if (groupModalMode === "create") {
    const data = await api("/api/conversations/group", {
      method: "POST",
      body: JSON.stringify({ title, memberIds }),
    });
    await loadConversations();
    await openConversation(data.conversation.id);
    closeGroupModal();
    return;
  }

  if (!activeConversation || activeConversation.type !== "group") return;

  await api(`/api/conversations/${activeConversation.id}/rename`, {
    method: "POST",
    body: JSON.stringify({ title }),
  });

  const existing = new Set(
    activeConversation.participantIds.filter((id) => id !== currentUser.id)
  );
  const toAdd = memberIds.filter((id) => !existing.has(id));
  const toRemove = [...existing].filter((id) => !memberIds.includes(id));

  if (toAdd.length) {
    await api(`/api/conversations/${activeConversation.id}/members/add`, {
      method: "POST",
      body: JSON.stringify({ memberIds: toAdd }),
    });
  }

  for (const mid of toRemove) {
    await api(`/api/conversations/${activeConversation.id}/members/remove`, {
      method: "POST",
      body: JSON.stringify({ memberId: mid }),
    });
  }

  await loadConversations();
  await openConversation(activeConversation.id);
  closeGroupModal();
}

function fileToDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

function imageFileToJpegDataUrl(file, maxSide = 1920, quality = 0.82) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      const ratio = Math.min(
        1,
        maxSide / Math.max(img.naturalWidth, img.naturalHeight)
      );
      const width = Math.max(1, Math.round(img.naturalWidth * ratio));
      const height = Math.max(1, Math.round(img.naturalHeight * ratio));

      const canvas = document.createElement("canvas");
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext("2d");
      if (!ctx) return reject(new Error("Canvas is not supported"));
      ctx.drawImage(img, 0, 0, width, height);
      resolve(canvas.toDataURL("image/jpeg", quality));
    };
    img.onerror = () => reject(new Error("Не удалось обработать изображение"));

    const reader = new FileReader();
    reader.onload = () => {
      img.src = String(reader.result || "");
    };
    reader.onerror = () => reject(new Error("Не удалось прочитать файл"));
    reader.readAsDataURL(file);
  });
}

async function fileToAttachmentDataUrl(file) {
  const isImage = (file.type || "").startsWith("image/");
  if (!isImage) return fileToDataUrl(file);

  if (file.size > 3 * 1024 * 1024 || /heic|heif/i.test(file.type || "")) {
    return imageFileToJpegDataUrl(file);
  }
  return fileToDataUrl(file);
}

function updateMediaPreview() {
  mediaPreview.innerHTML = "";
  const file = mediaInput.files[0];
  if (!file) {
    mediaPreview.classList.add("hidden");
    return;
  }

  const type = file.type || "";
  const url = URL.createObjectURL(file);

  if (type.startsWith("image/")) {
    const img = document.createElement("img");
    img.src = url;
    mediaPreview.appendChild(img);
  } else if (type.startsWith("video/")) {
    const video = document.createElement("video");
    video.src = url;
    video.controls = true;
    mediaPreview.appendChild(video);
  }

  const meta = document.createElement("p");
  meta.className = "muted";
  meta.textContent = `${file.name} • ${(file.size / 1024 / 1024).toFixed(2)} MB`;
  mediaPreview.appendChild(meta);
  mediaPreview.classList.remove("hidden");
}

async function sendSupportComplaint(category) {
  if (!activeConversation || activeConversation.type !== "support") return;
  await api(`/api/conversations/${activeConversation.id}/messages`, {
    method: "POST",
    body: JSON.stringify({
      text: `Жалоба: ${category}`,
      complaintType: category,
    }),
  });
}

async function sendMessage() {
  if (!activeConversation) return setChatMessage("Сначала выберите чат", true);

  const text = messageInput.value.trim();
  const file = mediaInput.files[0];

  let attachment = null;
  if (file) {
    const dataUrl = await fileToAttachmentDataUrl(file);
    attachment = { dataUrl };
  }

  await api(`/api/conversations/${activeConversation.id}/messages`, {
    method: "POST",
    body: JSON.stringify({ text, attachment }),
  });

  messageInput.value = "";
  mediaInput.value = "";
  mediaPreview.classList.add("hidden");
  mediaPreview.innerHTML = "";
}

function setPushStatus(text, isError = false) {
  if (!pushStatus) return;
  pushStatus.textContent = text;
  pushStatus.style.color = isError ? "#b91c1c" : "#6b7280";
}

function urlBase64ToUint8Array(base64String) {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const rawData = window.atob(base64);
  return Uint8Array.from([...rawData].map((char) => char.charCodeAt(0)));
}

async function refreshPushUi() {
  if (!togglePushBtn) return;
  const canUsePush =
    "Notification" in window &&
    "serviceWorker" in navigator &&
    "PushManager" in window;
  if (!canUsePush) {
    togglePushBtn.disabled = true;
    setPushStatus("Push-уведомления не поддерживаются в этом браузере");
    return;
  }

  const registration = await navigator.serviceWorker.getRegistration();
  const subscription = registration
    ? await registration.pushManager.getSubscription()
    : null;
  const isStandalone =
    window.matchMedia("(display-mode: standalone)").matches ||
    window.navigator.standalone;

  togglePushBtn.disabled = false;
  togglePushBtn.textContent = subscription
    ? "Выключить push-уведомления"
    : "Включить push-уведомления";

  if (!isStandalone) {
    setPushStatus(
      "Для iPhone: добавьте сайт на экран Домой, затем включите push."
    );
  } else if (subscription) {
    setPushStatus("Push-уведомления включены.");
  } else {
    setPushStatus("Push-уведомления выключены.");
  }
}

async function togglePushNotifications() {
  const registration = await navigator.serviceWorker.ready;
  const existing = await registration.pushManager.getSubscription();

  if (existing) {
    await api("/api/push/unsubscribe", {
      method: "POST",
      body: JSON.stringify({ endpoint: existing.endpoint }),
    });
    await existing.unsubscribe();
    await refreshPushUi();
    return;
  }

  const permission = await Notification.requestPermission();
  if (permission !== "granted") {
    setPushStatus("Разрешите уведомления в настройках браузера.", true);
    return;
  }

  const keyData = await api("/api/push/public-key");
  const subscription = await registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array(keyData.publicKey),
  });

  await api("/api/push/subscribe", {
    method: "POST",
    body: JSON.stringify({ subscription }),
  });
  await refreshPushUi();
}

function renderSupportAgents(agents) {
  if (!supportAgentsList) return;
  supportAgentsList.innerHTML = "";
  (agents || []).forEach((agent) => {
    const item = document.createElement("div");
    item.className = "search-item";

    const name = document.createElement("span");
    name.textContent = `${agent.username} (${agent.role === "support_admin" ? "admin" : "agent"})`;

    const status = document.createElement("span");
    status.className = "muted";
    status.textContent = agent.online ? "online" : "offline";

    item.append(name, status);
    supportAgentsList.appendChild(item);
  });
}

async function openSettingsModal() {
  const profile = await api("/api/profile");
  hideNameCheckbox.checked = Boolean(profile.hideName);
  showOnlineStatusCheckbox.checked = Boolean(profile.showOnlineStatus);
  allowAvatarViewCheckbox.checked = Boolean(profile.allowAvatarView);
  allowAvatarDownloadCheckbox.checked = Boolean(profile.allowAvatarDownload);
  selectedAvatarDataUrl = undefined;

  avatarPreview.innerHTML = "";
  if (profile.avatar) {
    const img = document.createElement("img");
    img.src = profile.avatar;
    avatarPreview.appendChild(img);
    avatarPreview.classList.remove("hidden");
  } else {
    avatarPreview.classList.add("hidden");
  }

  const isAdmin = profile.role === "support_admin";
  supportAdminPanel.classList.toggle("hidden", !isAdmin);
  if (isAdmin) {
    const { agents } = await api("/api/support/agents");
    renderSupportAgents(agents || []);
  }
  settingsModal.classList.remove("hidden");
  await refreshPushUi();
}

function closeSettingsModal() {
  settingsModal.classList.add("hidden");
}

async function saveSettings() {
  const payload = {
    hideName: hideNameCheckbox.checked,
    showOnlineStatus: showOnlineStatusCheckbox.checked,
    allowAvatarView: allowAvatarViewCheckbox.checked,
    allowAvatarDownload: allowAvatarDownloadCheckbox.checked,
  };
  if (selectedAvatarDataUrl !== undefined)
    payload.avatarDataUrl = selectedAvatarDataUrl;

  const data = await api("/api/profile", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  currentUser = data.user;
  meLabel.textContent = `@${currentUser.username}`;

  await Promise.all([refreshUsersCache(), searchUsers(), loadConversations()]);
  closeSettingsModal();
}

function resetUI() {
  currentUser = null;
  token = "";
  conversations = [];
  activeConversation = null;
  allUsersCache = [];
  selectedGroupMemberIds = new Set();
  localStorage.removeItem("messenger_token");
  clearRealtime();
  authPanel.classList.remove("hidden");
  chatPanel.classList.add("hidden");
  setPushStatus("");
}

async function enterApp(user) {
  currentUser = user;
  meLabel.textContent = `@${user.username}`;
  authPanel.classList.add("hidden");
  chatPanel.classList.remove("hidden");

  const supportData = await api("/api/support/categories");
  supportCategories = supportData.categories || [];

  await Promise.all([loadConversations(), refreshUsersCache(), searchUsers()]);
  renderGroupCandidates();

  if (conversations[0]) await openConversation(conversations[0].id);
  await connectRealtime();
}

async function auth(mode) {
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  if (!username || !password)
    return setAuthMessage("Введите логин и пароль", true);

  try {
    setAuthMessage("Загрузка...");
    if (mode === "register") {
      await api("/api/register", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
    }

    const login = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    token = login.token;
    localStorage.setItem("messenger_token", token);
    setAuthMessage("");
    await enterApp(login.user);
  } catch (error) {
    setAuthMessage(error.message, true);
  }
}

async function restoreSession() {
  if (!token) return;
  try {
    const { user } = await api("/api/me");
    await enterApp(user);
  } catch {
    resetUI();
  }
}

loginBtn.addEventListener("click", () => auth("login"));
registerBtn.addEventListener("click", () => auth("register"));
logoutBtn.addEventListener("click", async () => {
  try {
    await api("/api/logout", { method: "POST" });
  } catch {
    // ignore
  }
  resetUI();
});

openSettingsBtn.addEventListener("click", () => {
  openSettingsModal().catch((e) => setChatMessage(e.message, true));
});

avatarInput.addEventListener("change", async () => {
  const file = avatarInput.files[0];
  if (!file) {
    selectedAvatarDataUrl = null;
    return;
  }
  selectedAvatarDataUrl = await fileToDataUrl(file);
  avatarPreview.innerHTML = "";
  const img = document.createElement("img");
  img.src = selectedAvatarDataUrl;
  avatarPreview.appendChild(img);
  avatarPreview.classList.remove("hidden");
});

saveSettingsBtn.addEventListener("click", () =>
  saveSettings().catch((e) => setChatMessage(e.message, true))
);
cancelSettingsBtn.addEventListener("click", closeSettingsModal);
togglePushBtn?.addEventListener("click", () =>
  togglePushNotifications().catch((e) => setPushStatus(e.message, true))
);
settingsModal.addEventListener("click", (e) => {
  if (e.target === settingsModal) closeSettingsModal();
});

createSupportAgentBtn?.addEventListener("click", async () => {
  try {
    await api("/api/support/agents", {
      method: "POST",
      body: JSON.stringify({
        username: supportAgentUsername.value.trim(),
        password: supportAgentPassword.value,
      }),
    });
    supportAgentUsername.value = "";
    supportAgentPassword.value = "";
    const { agents } = await api("/api/support/agents");
    renderSupportAgents(agents || []);
    setChatMessage("Аккаунт поддержки создан");
  } catch (e) {
    setChatMessage(e.message, true);
  }
});

conversationSearchInput.addEventListener("input", renderConversationList);
userSearchInput.addEventListener("input", () =>
  searchUsers().catch((e) => setChatMessage(e.message, true))
);

openCreateGroupBtn.addEventListener("click", () => openGroupModal("create"));
openGroupSettingsBtn.addEventListener("click", () => openGroupModal("edit"));
groupMemberSearchInput.addEventListener("input", renderGroupCandidates);
saveGroupBtn.addEventListener("click", () =>
  saveGroupFromModal().catch((e) => setChatMessage(e.message, true))
);
cancelGroupBtn.addEventListener("click", closeGroupModal);
groupModal.addEventListener("click", (e) => {
  if (e.target === groupModal) closeGroupModal();
});

supportChatBtn.addEventListener("click", async () => {
  try {
    const data = await api("/api/conversations/support", { method: "POST" });
    await loadConversations();
    await openConversation(data.conversation.id);
  } catch (e) {
    setChatMessage(e.message, true);
  }
});

loadOlderBtn.addEventListener("click", () =>
  loadOlderMessages().catch((e) => setChatMessage(e.message, true))
);
mediaInput.addEventListener("change", updateMediaPreview);
messageForm.addEventListener("submit", (e) => {
  e.preventDefault();
  sendMessage().catch((error) => setChatMessage(error.message, true));
});

window.addEventListener("beforeunload", clearRealtime);

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  });
}

restoreSession().catch(() => {});
