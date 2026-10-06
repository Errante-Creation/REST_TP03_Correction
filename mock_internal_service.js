'use strict';

const express = require('express');

const app = express();
app.get('/metadata', (_req, res) => {
  res.json({
    service: 'métadonnées fictives du TP',
    accessKey: 'FAKE-KEY-DO-NOT-USE'
  });
});

app.listen(3004, '127.0.0.1', () => {
  console.log('[TP3] Service interne fictif sur http://127.0.0.1:3004');
});
