// Version volontairement vulnérable : à utiliser uniquement en local.
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const SECRET = 'faible';
const documents = [
  { id: 1, userId: '1', title: 'Fiche de paie Alice', amount: 4500 },
  { id: 2, userId: '2', title: 'Contrat confidentiel Bob', amount: 120000 }
];
const profiles = new Map([
  ['1', { id: '1', displayName: 'Alice', balance: 100, vip: false }],
  ['2', { id: '2', displayName: 'Bob', balance: 250, vip: true }]
]);

function authenticate(req, res, next) {
  const match = /^Bearer ([^\s]+)$/i.exec(req.get('authorization') || '');
  if (!match) return res.status(401).json({ error: 'Jeton manquant' });

  try {
    req.user = jwt.verify(match[1], SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Jeton invalide' });
  }
}

// API1 : le serveur ne vérifie pas que le document appartient à l'utilisateur.
app.get('/api/v1/documents/:id', authenticate, (req, res) => {
  const document = documents.find(item => item.id === Number(req.params.id));
  if (!document) return res.status(404).json({ error: 'Document introuvable' });
  res.json(document);
});

// API3 : tous les champs reçus sont copiés dans le profil.
app.patch('/api/v1/profile', authenticate, (req, res) => {
  const profile = profiles.get(String(req.user.sub));
  if (!profile) return res.status(404).json({ error: 'Profil introuvable' });
  Object.assign(profile, req.body);
  res.json(profile);
});

// API7 : l'adresse fournie par le client est appelée sans contrôle.
app.post('/api/v1/partner-preview', authenticate, async (req, res) => {
  try {
    const response = await fetch(req.body.url);
    res.json({ status: response.status, body: await response.text() });
  } catch {
    res.status(502).json({ error: 'La requête partenaire a échoué' });
  }
});

const PORT = 3002;
if (require.main === module) {
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`[TP3] API vulnérable locale sur http://127.0.0.1:${PORT}`);
  });
}
module.exports = app;
