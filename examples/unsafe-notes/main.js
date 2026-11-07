// A small notes app that makes every classic Electron mistake, for the demo. Do not copy it.
const { app, BrowserWindow, ipcMain, shell, Menu } = require('electron');
const fs = require('fs');

app.setAsDefaultProtocolClient('unsafe-notes');

function createWindow() {
  const win = new BrowserWindow({
    width: 1100,
    height: 720,
    title: 'Unsafe Notes',
    webPreferences: { nodeIntegration: true, contextIsolation: false, webSecurity: false, sandbox: false },
  });
  win.loadFile('index.html');
  win.webContents.on('new-window', (event, url) => shell.openExternal(url));
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: 'File', submenu: [{ label: 'New Note' }, { label: 'Export as PDF' }] },
    { label: 'Help', submenu: [{ label: 'Check for Updates' }] },
  ]));
}

ipcMain.handle('notes:load', (event, file) => fs.readFileSync(file, 'utf8'));
ipcMain.handle('notes:save', (event, file, text) => fs.writeFileSync(file, text));
app.whenReady().then(createWindow);
