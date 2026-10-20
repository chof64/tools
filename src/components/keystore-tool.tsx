import { useEffect, useRef, useState } from "react";
import { Upload } from "lucide-react";
import { Button } from "~/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "~/components/ui/card";
import { cn } from "~/lib/utils";
import { getSigningFingerprints, parseKeyProperties, type SigningFingerprints } from "~/lib/android-keystore";

const KEYSTORE_EXTENSIONS = [".jks", ".keystore", ".p12", ".pfx"];
const PROPERTIES_EXTENSIONS = [".properties", ".txt"];

function FileDropZone({
  title,
  description,
  fileName,
  extensions,
  onFile,
  onInvalid,
}: {
  title: string;
  description: string;
  fileName: string;
  extensions: readonly string[];
  onFile: (file: File) => void;
  onInvalid: (message: string) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const dragDepth = useRef(0);
  const [dragging, setDragging] = useState(false);

  function acceptFiles(files: FileList | null) {
    if (!files?.length) return;
    if (files.length !== 1) {
      onInvalid("Select one file at a time for " + title.toLowerCase() + ".");
      return;
    }
    const selected = files[0];
    if (!extensions.some((extension) => selected.name.toLowerCase().endsWith(extension))) {
      onInvalid("Wrong file type for " + title.toLowerCase() + ". Choose " + extensions.join(", ") + ".");
      return;
    }
    onFile(selected);
  }

  function resetDrag() {
    dragDepth.current = 0;
    setDragging(false);
  }

  useEffect(() => {
    window.addEventListener("drop", resetDrag);
    window.addEventListener("dragend", resetDrag);
    return () => {
      window.removeEventListener("drop", resetDrag);
      window.removeEventListener("dragend", resetDrag);
    };
  }, []);

  return (
    <div className="min-w-0">
      <input
        ref={inputRef}
        type="file"
        accept={extensions.join(",")}
        className="hidden"
        tabIndex={-1}
        onChange={(event) => {
          acceptFiles(event.target.files);
          event.target.value = "";
        }}
      />
      <button
        type="button"
        onClick={() => inputRef.current?.click()}
        onDragEnter={(event) => {
          if (!event.dataTransfer.types.includes("Files")) return;
          event.preventDefault();
          dragDepth.current++;
          setDragging(true);
        }}
        onDragOver={(event) => {
          if (!event.dataTransfer.types.includes("Files")) return;
          event.preventDefault();
          event.dataTransfer.dropEffect = "copy";
          setDragging(true);
        }}
        onDragLeave={(event) => {
          event.preventDefault();
          dragDepth.current = Math.max(0, dragDepth.current - 1);
          if (dragDepth.current === 0) setDragging(false);
        }}
        onDrop={(event) => {
          event.preventDefault();
          resetDrag();
          acceptFiles(event.dataTransfer.files);
        }}
        className={cn(
          "flex min-h-44 w-full cursor-pointer flex-col items-center justify-center gap-2 rounded-2xl border-2 border-dashed p-5 text-center outline-none transition-colors duration-150 focus-visible:ring-2 focus-visible:ring-ring/40",
          dragging
            ? "border-primary bg-primary/10 ring-2 ring-primary/20"
            : "border-border bg-background/70 hover:border-primary/50 hover:bg-muted/60"
        )}
      >
        <Upload aria-hidden="true" className={cn("size-7", dragging ? "text-primary" : "text-muted-foreground")} />
        <span className="text-sm font-semibold">{title}</span>
        <span className={cn("max-w-full break-all text-xs leading-5", fileName ? "font-medium text-foreground" : "text-muted-foreground")}>
          {dragging ? "Release to select this file" : fileName || description}
        </span>
        <span className="text-xs text-muted-foreground">
          {dragging ? "Drop file here" : "Drag and drop here, or click to browse"}
        </span>
      </button>
    </div>
  );
}

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
  const propertiesRequest = useRef(0);

  // Cancel stale fingerprint calculations without canceling a properties read during a second file drop.
  function clearOutput() {
    request.current++;
    setResult(null);
    setError("");
    setBusy(false);
  }

  function reportInvalid(message: string) {
    clearOutput();
    setError(message);
  }

  function chooseKeystore(selected: File) {
    clearOutput();
    if (selected.size > 10 * 1024 * 1024) {
      setError("Keystore must be smaller than 10 MB.");
      return;
    }
    setFile(selected);
  }

  async function readProperties(input: File) {
    clearOutput();
    const current = ++propertiesRequest.current;
    setPropertiesFile("");
    if (input.size > 64 * 1024) {
      setError("Properties file must be smaller than 64 KB.");
      return;
    }
    try {
      const values = parseKeyProperties(await input.text());
      if (current !== propertiesRequest.current) return;
      if (values.storePassword === undefined && values.keyAlias === undefined) {
        throw new Error("Missing storePassword and keyAlias in properties file.");
      }
      clearOutput();
      setPropertiesFile(input.name);
      setPassword(values.storePassword ?? "");
      setPasswordKnown(values.storePassword !== undefined);
      setAlias(values.keyAlias ?? "");
    } catch (cause) {
      if (current === propertiesRequest.current) setError(cause instanceof Error ? cause.message : "Invalid properties file.");
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
    propertiesRequest.current++;
    clearOutput();
    setFile(null);
    setPropertiesFile("");
    setPassword("");
    setPasswordKnown(false);
    setAlias("");
  }

  useEffect(() => {
    // A file dropped outside both boxes must not navigate the browser away from this page.
    function preventFileNavigation(event: DragEvent) {
      if (event.dataTransfer?.types.includes("Files") || event.dataTransfer?.files.length) {
        event.preventDefault();
      }
    }
    window.addEventListener("dragover", preventFileNavigation);
    window.addEventListener("drop", preventFileNavigation);
    return () => {
      window.removeEventListener("dragover", preventFileNavigation);
      window.removeEventListener("drop", preventFileNavigation);
    };
  }, []);

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <Card className="tool-panel gap-0 py-0">
        <CardHeader className="border-b border-border/60 px-5 py-5 sm:px-6">
          <CardTitle>Android signing certificate</CardTitle>
          <CardDescription>Select your upload keystore and optional key.properties to get its signing certificate fingerprints.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5 px-5 py-6 sm:px-6">
          <div className="grid gap-4 sm:grid-cols-2">
            <FileDropZone
              title="Upload keystore"
              description="Choose .jks, .keystore, .p12, or .pfx"
              fileName={file?.name ?? ""}
              extensions={KEYSTORE_EXTENSIONS}
              onFile={chooseKeystore}
              onInvalid={reportInvalid}
            />
            <FileDropZone
              title="key.properties (optional)"
              description="Read storePassword and keyAlias automatically"
              fileName={propertiesFile}
              extensions={PROPERTIES_EXTENSIONS}
              onFile={(selected) => void readProperties(selected)}
              onInvalid={reportInvalid}
            />
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="space-y-2 text-sm font-medium">
              <span>Store password</span>
              <input type="password" autoComplete="off" spellCheck={false} value={password} onChange={(event) => {
                propertiesRequest.current++;
                clearOutput();
                setPassword(event.target.value);
                setPasswordKnown(true);
              }} placeholder="From storePassword" className="w-full rounded-xl border border-border bg-background/80 px-3 py-2.5 font-mono text-sm outline-none focus:ring-2 focus:ring-ring/30" />
            </label>
            <label className="space-y-2 text-sm font-medium">
              <span>Key alias (optional with one certificate)</span>
              <input type="text" autoComplete="off" spellCheck={false} value={alias} onChange={(event) => {
                propertiesRequest.current++;
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
