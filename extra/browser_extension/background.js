let networkData = [];


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
      sendEvents();
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