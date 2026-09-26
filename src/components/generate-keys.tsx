import  { useState, useEffect } from 'react';
import { exportJWK, exportPKCS8, generateKeyPair } from "jose";
import {
	Card,
	CardAction,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "~/components/ui/card";
import { Button } from "~/components/ui/button";

export default function GenerateKeys() {
  const [privateKey, setPrivateKey] = useState('');
  const [jwks, setJwks] = useState('');

  useEffect(() => {
    const generateKeys = async () => {
      const keys = await generateKeyPair("RS256", {
        extractable: true,
      });
      const privKey = (await exportPKCS8(keys.privateKey))
        .trimEnd()
        .replace(/\n/g, " "); // Always single-line like original script
      const pubKey = await exportJWK(keys.publicKey);
      const jwksData = JSON.stringify({ keys: [{ use: "sig", ...pubKey }] }); // Always compact
      
      setPrivateKey(privKey);
      setJwks(jwksData);
    };
    generateKeys();
  }, []);

  const copyPrivate = () => {
    navigator.clipboard.writeText(privateKey);
  };

  const copyJwks = () => {
    navigator.clipboard.writeText(jwks);
  };

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      {/* Private Key Section */}
      <Card className="tool-panel gap-0 py-0">
        <CardHeader className="border-b border-border/60 px-5 py-5 sm:px-6">
          <CardTitle>Private signing key</CardTitle>
          <CardDescription>
            This private key is used to sign your JWTs. Keep it secure and never
            share it.
          </CardDescription>
          <CardAction className="col-start-1 row-start-3 self-center justify-self-start sm:col-start-2 sm:row-span-2 sm:row-start-1 sm:justify-self-end">
            <Button onClick={copyPrivate}>Copy</Button>
          </CardAction>
        </CardHeader>
        <CardContent className="px-5 py-5 sm:px-6 sm:py-6">
          <pre className="tool-code h-72 overflow-x-auto p-4 font-mono text-sm leading-6 wrap-break-word whitespace-pre-wrap">
            <code>{privateKey}</code>
          </pre>
        </CardContent>
      </Card>

      {/* JWKS Section */}
      <Card className="tool-panel gap-0 py-0">
        <CardHeader className="border-b border-border/60 px-5 py-5 sm:px-6">
          <CardTitle>JWKS (JSON Web Key Set)</CardTitle>
          <CardDescription>
            This JWKS contains your public key for verifying JWT signatures. Share
            it with clients.
          </CardDescription>
          <CardAction className="col-start-1 row-start-3 self-center justify-self-start sm:col-start-2 sm:row-span-2 sm:row-start-1 sm:justify-self-end">
            <Button onClick={copyJwks}>Copy</Button>
          </CardAction>
        </CardHeader>
        <CardContent className="px-5 py-5 sm:px-6 sm:py-6">
          <pre className="tool-code h-72 overflow-x-auto p-4 font-mono text-sm leading-6 wrap-break-word whitespace-pre-wrap">
            <code>{jwks}</code>
          </pre>
        </CardContent>
      </Card>
    </div>
  );
}
