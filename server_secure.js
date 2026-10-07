// Version volontairement vulnérable : à utiliser uniquement en local.
const express = require('express');
require('dotenv').config()
const jwt = require('jsonwebtoken');
const { z } = require('zod')

const app = express();
app.use(express.json({ limit: '16kb' }));

const documents = [
  { id: 1, userId: '1', title: 'Fiche de paie Alice', amount: 4500 },
  { id: 2, userId: '2', title: 'Contrat confidentiel Bob', amount: 120000 }
];
const profiles = new Map([
  ['1', { id: '1', displayName: 'Alice', balance: 100, vip: false }],
  ['2', { id: '2', displayName: 'Bob', balance: 250, vip: true }]
]);

function jwtSecret(){
    const secret = process.env.JWT_SECRET;
    if(!secret || Buffer.byteLength(secret, 'utf8') < 32){
        throw new Error('JWT_SECRET doit contenir au moins 32 octets')
    }
    return secret;
}


function authenticate(req, res, next) {
  const match = /^Bearer ([^\s]+)$/i.exec(req.get('authorization') || '');
  if (!match) return res.status(401).json({ error: 'Jeton manquant' });

  try {
    // req.user = jwt.verify(match[1], SECRET);
    const user = jwt.verify(match[1], jwtSecret(), { algorithms: ['HS256'] });
    if((typeof user.sub !== 'string' && typeof user.sub != 'number') || typeof user.exp !== 'number'){
        return res.status(401).json({ error: 'Le jeton doit contenir un sujet et une expiration' })
    }

    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Jeton invalide ou expiré' });
  }
}

// Gestion des schemas Zod
const profileSchema = z.object({
    displayName: z.string().trim().min(2).max(80)
}).strict();

const partnerSchema = z.object({
    partnerId: z.enum(['payroll'])
})

// Middleware de validation du schema zod
function validate(schema){
  return (req, res, next) => {
    const result = schema.safeParse(req.body);
    if(!result.success) return res.status(422).json({error: 'Données invalides'});
    req.body = result.data;
    next();
  };
}


// API1 : le serveur ne vérifie pas que le document appartient à l'utilisateur.
app.get('/api/v1/documents/:id', authenticate, (req, res) => {
  const document = documents.find(item => item.id === Number(req.params.id));
  if (!document) return res.status(404).json({ error: 'Document introuvable' });

  if(document.userId !== String(req.user.sub) && req.user.role !== 'admin'){
    return res.status(403).json({error: 'Accès refusé'})
  }

  res.json(document);
});

// API3 : tous les champs reçus sont copiés dans le profil.
app.patch('/api/v1/profile', authenticate, validate(profileSchema), (req, res) => {
  const profile = profiles.get(String(req.user.sub));
  if (!profile) return res.status(404).json({ error: 'Profil introuvable' });
  
  profile.displayName = req.body.displayName;
  res.json({
    id: profile.id,
    displayName: profile.displayName
  });
});

// API7 : l'adresse fournie par le client est appelée sans contrôle.
app.post('/api/v1/partner-preview', authenticate, validate(partnerSchema), async (req, res) => {
  res.json({ partner: req.body.partnerId, status: 'preview disponible'})
});

const PORT = 3002;
if (require.main === module) {
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`[TP3] API secure locale sur http://127.0.0.1:${PORT}`);
  });
}
module.exports = app;
