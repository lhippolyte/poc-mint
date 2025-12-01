// index.js — POC backend pour offre entreprise

import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

// Liste des emails autorisés pour Orange (POC)
const authorizedEmails = [
  "hippolyte.lacassagne@gmail.com",
  "test@orange.fr",
  "test2@orange.fr"
];

// Shared secret de l’app proxy Shopify (à récupérer dans ton admin)
const APP_PROXY_SECRET = process.env.SHOPIFY_API_SECRET;

// Verification HMAC — sécurité App Proxy
function validateHMAC(query) {
  const signature = query.signature;
  if (!signature) {
    console.log("No signature found");
    return false;
  }

  // Copie des paramètres et suppression de la signature
  const params = { ...query };
  delete params.signature;

  const message = Object.keys(params)
    .sort()
    .map((key) => `${key}=${params[key]}`)
    .join("");

  const generated = crypto
    .createHmac("sha256", APP_PROXY_SECRET)
    .update(message)
    .digest("hex");

    console.log('validateHMAC generated',generated);
    console.log('validateHMACy signature',signature);
  return generated === signature;
}

// Route App Proxy : /apps/verify
app.get("/verify", async (req, res) => {
    console.log('inside app get verify req.query',req.query);
    
  const { email, company } = req.query;
  console.log('inside app get verify email',email);

  if (!validateHMAC(req.query)) {
    return res.status(403).send("Invalid signature");
  }

  if (!email || !company) {
    return res.status(400).send("Missing parameters");
  }

  const normalized = email.toLowerCase().trim();
  const isAllowed = authorizedEmails.includes(normalized);

  if (!isAllowed) {
    return res.send(`
      <h1>Accès refusé</h1>
      <p>Votre adresse (${email}) n'est pas autorisée pour l'offre entreprise Orange.</p>
    `);
  }

  // Si email autorisé → redirection vers la page entreprise
  return res.redirect(`/pages/offre-entreprise?company=${company}`);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend POC running on ${PORT}`));
