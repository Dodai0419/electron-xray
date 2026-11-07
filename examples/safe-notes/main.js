// The same app with its holes closed.
const { app, BrowserWindow, ipcMain, session, shell, Menu } = require('electron');
const path = require('path');

function createWindow() {
  const win = new BrowserWindow({
    width: 1100,
    height: 720,
    title: 'Safe Notes',
    webPreferences: { preload: path.join(__dirname, 'preload.js') },
  });
  win.loadFile('index.html');
  win.webContents.on('will-navigate', (event) => event.preventDefault());
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (new URL(url).protocol === 'https:') shell.openExternal(url);
    return { action: 'deny' };
  });
  session.defaultSession.setPermissionRequestHandler((wc, permission, done) => done(false));
}

ipcMain.handle('notes:load', () => 'Hello');
app.whenReady().then(createWindow);
