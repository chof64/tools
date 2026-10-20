import { useRef, useState } from "react";
import { Button } from "~/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "~/components/ui/card";
import { getSigningFingerprints, parseKeyProperties, type SigningFingerprints } from "~/lib/android-keystore";

export default function KeystoreTool() {
  const [file, setFile] = useState<File | null>(null);
  const [propertiesFile, setPropertiesFile] = useState("");
  const [password, setPassword] = useState("");
  const [passwordKnown, setPasswordKnown] = useState(false);
  const [alias, setAlias] = useState("");
  const [result, setResult] = useState<SigningFingerprints | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const request = useRef(0);

  function clearOutput() {
    request.current++;
    setResult(null);
    setError("");
    setBusy(false);
  }

  async function readProperties(input: File) {
    clearOutput();
    const current = request.current;
    if (input.size > 64 * 1024) {
      setError("Properties file must be smaller than 64 KB.");
      return;
    }
    try {
      const values = parseKeyProperties(await input.text());
      if (current !== request.current) return;
      if (values.storePassword === undefined && values.keyAlias === undefined) {
        throw new Error("Missing storePassword and keyAlias in properties file.");
      }
      setPropertiesFile(input.name);
      setPassword(values.storePassword ?? "");
      setPasswordKnown(values.storePassword !== undefined);
      setAlias(values.keyAlias ?? "");
    } catch (cause) {
      if (current === request.current) setError(cause instanceof Error ? cause.message : "Invalid properties file.");
    }
  }

  async function extract() {
    if (!file) return;
    if (!passwordKnown) {
      setError("Provide storePassword in key.properties or manually enter it.");
      return;
    }
    clearOutput();
    const current = request.current;
    setBusy(true);
    try {
      const details = await getSigningFingerprints(await file.arrayBuffer(), password, alias);
      if (current === request.current) setResult(details);
    } catch (cause) {
      if (current === request.current) setError(cause instanceof Error ? cause.message : "Could not read the keystore.");
    } finally {
      if (current === request.current) setBusy(false);
    }
  }

  function reset() {
    clearOutput();
    setFile(null);
    setPropertiesFile("");
    setPassword("");
    setPasswordKnown(false);
    setAlias("");
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <Card className="tool-panel gap-0 py-0">
        <CardHeader className="border-b border-border/60 px-5 py-5 sm:px-6">
          <CardTitle>Android signing certificate</CardTitle>
          <CardDescription>Select your upload keystore and optional key.properties to get its signing certificate fingerprints.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5 px-5 py-6 sm:px-6">
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="flex cursor-pointer flex-col gap-2 rounded-2xl border-2 border-dashed border-border bg-background/70 p-5 text-sm hover:bg-muted/60">
              <span className="font-semibold">Upload keystore</span>
              <span className="break-all text-muted-foreground">{file?.name || "Choose .jks, .keystore, .p12, or .pfx"}</span>
              <input className="text-xs" type="file" accept=".jks,.keystore,.p12,.pfx" onChange={(event) => {
                const selected = event.target.files?.[0];
                if (selected) {
                  clearOutput();
                  if (selected.size > 10 * 1024 * 1024) {
                    setError("Keystore must be smaller than 10 MB.");
                    setFile(null);
                  } else setFile(selected);
                }
                event.target.value = "";
              }} />
            </label>
            <label className="flex cursor-pointer flex-col gap-2 rounded-2xl border-2 border-dashed border-border bg-background/70 p-5 text-sm hover:bg-muted/60">
              <span className="font-semibold">key.properties (optional)</span>
              <span className="break-all text-muted-foreground">{propertiesFile || "Automatically read storePassword and keyAlias"}</span>
              <input className="text-xs" type="file" accept=".properties,.txt" onChange={(event) => {
                const selected = event.target.files?.[0];
                if (selected) void readProperties(selected);
                event.target.value = "";
              }} />
            </label>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="space-y-2 text-sm font-medium">
              <span>Store password</span>
              <input type="password" autoComplete="off" spellCheck={false} value={password} onChange={(event) => {
                clearOutput();
                setPassword(event.target.value);
                setPasswordKnown(true);
              }} placeholder="From storePassword" className="w-full rounded-xl border border-border bg-background/80 px-3 py-2.5 font-mono text-sm outline-none focus:ring-2 focus:ring-ring/30" />
            </label>
            <label className="space-y-2 text-sm font-medium">
              <span>Key alias (optional with one certificate)</span>
              <input type="text" autoComplete="off" spellCheck={false} value={alias} onChange={(event) => {
                clearOutput();
                setAlias(event.target.value);
              }} placeholder="e.g. upload" className="w-full rounded-xl border border-border bg-background/80 px-3 py-2.5 font-mono text-sm outline-none focus:ring-2 focus:ring-ring/30" />
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button disabled={!file || busy} onClick={() => void extract()}>{busy ? "Reading certificate…" : "Get fingerprints"}</Button>
            <Button variant="outline" onClick={reset}>Clear</Button>
          </div>
          {error && <p role="alert" className="rounded-xl border border-destructive/30 px-4 py-3 text-sm text-destructive">{error}</p>}
          <p className="text-xs leading-5 text-muted-foreground">Processed entirely in your browser. The keystore, properties file, and passwords are never uploaded, saved, or logged. The key password is not required.</p>
        </CardContent>
      </Card>
      {result && (
        <Card className="tool-panel gap-0 py-0">
          <CardHeader className="border-b border-border/60 px-5 py-5 sm:px-6">
            <CardTitle>Certificate fingerprints</CardTitle>
            <CardDescription>{result.format} · Alias: {result.alias}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 px-5 py-6 sm:px-6">
            {([["SHA-1", result.sha1], ["SHA-256", result.sha256]] as const).map(([label, value]) => (
              <div key={label} className="rounded-2xl border border-border bg-background/80 p-4">
                <div className="mb-2 flex items-center justify-between">
                  <h3 className="font-semibold">{label}</h3>
                  <Button variant="outline" size="sm" onClick={() => void navigator.clipboard.writeText(value)}>Copy</Button>
                </div>
                <output className="block break-all font-mono text-sm leading-6 select-all">{value}</output>
              </div>
            ))}
            <p className="text-xs leading-5 text-muted-foreground">These identify your upload certificate. If Google Play App Signing is enabled, the app signing certificate may differ.</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
