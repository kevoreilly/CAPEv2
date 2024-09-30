let isTORBrowser = false;
let networkData = [];
let downloadTORPath = "bext_default.json";

function generateRandomFilename() {
  const asciiLetters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let filename = 'bext_';
  for (let i = 0; i < 10; i++) {
    filename += asciiLetters.charAt(Math.floor(Math.random() * asciiLetters.length));
  }
  filename += '.json';
  return filename;
}


function storeNetworkData() {
  const blob = new Blob([JSON.stringify(networkData, null, 2)], {type: "application/json"});
  const url = URL.createObjectURL(blob);

  browser.downloads.download({
    url: url,
    filename: downloadTORPath,
    conflictAction: 'overwrite'
  });
}

function onRequestEvent(details) {
    if (details.url.includes("/browser_extension")) {
      return;
    }
    const requestEvent = networkData.find(entry => entry.url === details.url);
    if (requestEvent) {
      return
    }
    const info = {
        url: details.url,
        method: details.method,
        timeStamp: details.timeStamp,
        requestHeaders: details.requestHeaders,
    };
    networkData.push(info);
}

function onResponseEvent(details) {
  const requestEvent = networkData.find(entry => entry.url === details.url);
  if (requestEvent) {
      if (requestEvent.ip) {
        return;
      }
      requestEvent.responseHeaders = details.responseHeaders;
      requestEvent.type = details.type;
      requestEvent.ip = details.ip;
      requestEvent.originUrl = details.originUrl;
      if (isTORBrowser) {
        storeNetworkData();
      } else {
        sendEvents()
      }
  }
}

function sendEvents() {
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

browser.downloads.onCreated.addListener(function(downloadItem) {
  const downloadId = downloadItem.id;
  browser.downloads.onChanged.addListener(function(delta) {
    if (delta.id === downloadId && delta.state && delta.state.current === "complete") {
      const requestEvent = networkData.find(entry => entry.url === downloadItem.url);
      if (requestEvent) {
        requestEvent.filePath = downloadItem.filename;
      }
    }
  });
});

browser.runtime.onStartup.addListener(function () {
  networkData = [];
});

browser.runtime.getBrowserInfo().then((bInfo) => {
  if (bInfo.vendor === "Tor Project") {
    isTORBrowser = true;
    downloadTORPath = generateRandomFilename();
  }
});