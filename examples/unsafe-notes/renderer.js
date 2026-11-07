const { marked } = require('marked');
const { ipcRenderer } = require('electron');

async function show(file) {
  const text = await ipcRenderer.invoke('notes:load', file);
  document.getElementById('note').innerHTML = marked(text);
}
window.addEventListener('message', (event) => show(event.data));
show(location.hash.slice(1));
