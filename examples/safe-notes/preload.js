const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('notes', { load: () => ipcRenderer.invoke('notes:load') });
