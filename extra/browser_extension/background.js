let isTORBrowser = false;
let networkData = [];
let requestsById = new Map();
let entriesByDedupKey = new Map();
let downloadTORPath = "bext_default.json";
const MAX_RAW_BODY_BYTES = 4096;

function generateRandomFilename() {
  const asciiLetters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let filename = 'bext_';
  for (let i = 0; i < 10; i++) {
    filename += asciiLetters.charAt(Math.floor(Math.random() * asciiLetters.length));
  }
  filename += '.json';
  return filename;
}

function serializeRequestBody(requestBody) {
  if (!requestBody) {
    return undefined;
  }
  const result = {};
  if (requestBody.formData) {
    result.formData = requestBody.formData;
  }
  if (Array.isArray(requestBody.raw)) {
    result.raw = requestBody.raw.map(part => {
      if (part && part.bytes) {
        const bytes = new Uint8Array(part.bytes.slice(0, MAX_RAW_BODY_BYTES));
        return new TextDecoder("utf-8", {fatal: false}).decode(bytes);
      }
      if (part && part.file) {
        return `[file:${part.file}]`;
      }
      return "";
    });
  }
  if (requestBody.error) {
    result.error = requestBody.error;
  }
  return Object.keys(result).length ? result : undefined;
}

function requestDedupKey(url, method, requestBody) {
  return `${method || "GET"} ${url} ${requestBody ? JSON.stringify(requestBody) : ""}`;
}

let storeTimeout = null;
let lastStoreTime = 0;
const STORE_DEBOUNCE_MS = 500;
const STORE_MAX_WAIT_MS = 2000;

function flushStoreNetworkData() {
  if (storeTimeout) {
    clearTimeout(storeTimeout);
    storeTimeout = null;
  }
  lastStoreTime = Date.now();
  const blob = new Blob([JSON.stringify(networkData, null, 2)], {type: "application/json"});
  const url = URL.createObjectURL(blob);

  browser.downloads.download({
    url: url,
    filename: downloadTORPath,
    conflictAction: 'overwrite'
  });
}

function storeNetworkData() {
  const now = Date.now();
  if (!lastStoreTime) {
    lastStoreTime = now;
  }
  if (now - lastStoreTime >= STORE_MAX_WAIT_MS) {
    flushStoreNetworkData();
    return;
  }
  if (storeTimeout) {
    clearTimeout(storeTimeout);
  }
  storeTimeout = setTimeout(flushStoreNetworkData, STORE_DEBOUNCE_MS);
}

function onBeforeRequestEvent(details) {
  if (details.url.includes("/browser_extension")) {
    return;
  }
  const requestBody = serializeRequestBody(details.requestBody);
  const key = requestDedupKey(details.url, details.method, requestBody);
  const existing = entriesByDedupKey.get(key);
  if (existing) {
    requestsById.set(details.requestId, existing);
    return;
  }
  const info = {
    url: details.url,
    method: details.method,
    timeStamp: details.timeStamp,
  };
  if (requestBody !== undefined) {
    info.requestBody = requestBody;
  }
  networkData.push(info);
  entriesByDedupKey.set(key, info);
  requestsById.set(details.requestId, info);
}

function onRequestEvent(details) {
  if (details.url.includes("/browser_extension")) {
    return;
  }
  let requestEvent = requestsById.get(details.requestId);
  if (!requestEvent) {
    requestEvent = networkData.find(
      entry => entry.url === details.url && entry.method === details.method
    );
  }
  if (!requestEvent) {
    requestEvent = {
      url: details.url,
      method: details.method,
      timeStamp: details.timeStamp,
    };
    networkData.push(requestEvent);
    requestsById.set(details.requestId, requestEvent);
  }
  if (!requestEvent.requestHeaders) {
    requestEvent.requestHeaders = details.requestHeaders;
  }
}

function onResponseEvent(details) {
  const requestEvent = requestsById.get(details.requestId) ||
    networkData.find(entry => entry.url === details.url);
  requestsById.delete(details.requestId);
  if (requestEvent) {
    if (requestEvent.ip) {
      return;
    }
    requestEvent.statusCode = details.statusCode;
    requestEvent.responseHeaders = details.responseHeaders;
    requestEvent.type = details.type;
    requestEvent.ip = details.ip;
    requestEvent.originUrl = details.originUrl;
    if (isTORBrowser) {
      storeNetworkData();
    } else {
      sendEvents();
    }
  }
}

let sendTimeout = null;
let lastSendTime = 0;
const SEND_DEBOUNCE_MS = 500;
const SEND_MAX_WAIT_MS = 2000;

function flushSendEvents() {
  if (sendTimeout) {
    clearTimeout(sendTimeout);
    sendTimeout = null;
  }
  lastSendTime = Date.now();
  const form = new FormData();
  form.append('networkData', JSON.stringify(networkData));

  fetch('http://localhost:8000/browser_extension', {
    method: 'POST',
    body: form
  })
  .then(response => response.json())
  .catch(error => {
    console.error('Error posting data to endpoint:', error);
  });
}

function sendEvents() {
  const now = Date.now();
  if (!lastSendTime) {
    lastSendTime = now;
  }
  if (now - lastSendTime >= SEND_MAX_WAIT_MS) {
    flushSendEvents();
    return;
  }
  if (sendTimeout) {
    clearTimeout(sendTimeout);
  }
  sendTimeout = setTimeout(flushSendEvents, SEND_DEBOUNCE_MS);
}

browser.webRequest.onBeforeRequest.addListener(
  onBeforeRequestEvent,
  {urls: ["<all_urls>"]},
  ["requestBody"]
);

browser.webRequest.onBeforeSendHeaders.addListener(
  onRequestEvent,
  {urls: ["<all_urls>"]},
  ["requestHeaders"]
);

browser.webRequest.onCompleted.addListener(
  onResponseEvent,
  {urls: ["<all_urls>"]},
  ["responseHeaders"]
);

browser.webRequest.onErrorOccurred.addListener(
  function(details) {
    requestsById.delete(details.requestId);
  },
  {urls: ["<all_urls>"]}
);

browser.downloads.onChanged.addListener(function(delta) {
  if (delta.state && delta.state.current === "complete") {
    browser.downloads.search({id: delta.id}).then(items => {
      if (items && items.length > 0) {
        const downloadItem = items[0];
        const requestEvent = networkData.find(entry => entry.url === downloadItem.url);
        if (requestEvent) {
          requestEvent.filePath = downloadItem.filename;
        }
      }
    });
  }
});

browser.runtime.onStartup.addListener(function () {
  networkData = [];
  requestsById.clear();
  entriesByDedupKey.clear();
  if (storeTimeout) {
    clearTimeout(storeTimeout);
    storeTimeout = null;
  }
  if (sendTimeout) {
    clearTimeout(sendTimeout);
    sendTimeout = null;
  }
  lastStoreTime = 0;
  lastSendTime = 0;
});

browser.runtime.getBrowserInfo().then((bInfo) => {
  if (bInfo.vendor === "Tor Project") {
    isTORBrowser = true;
    downloadTORPath = generateRandomFilename();
  }
});
