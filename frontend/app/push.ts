export type PushBrowserFamily = "chromium" | "firefox" | "safari" | "other";

export type PushClientEnvironment = {
  browser: PushBrowserFamily;
  ios: boolean;
  standalone: boolean;
};

export function classifyPushClient(
  userAgent: string,
  platform: string,
  maxTouchPoints: number,
  standalone: boolean,
): PushClientEnvironment {
  const agent = userAgent.toLowerCase();
  const normalizedPlatform = platform.toLowerCase();
  const ios =
    /iphone|ipad|ipod/.test(agent) || (/mac/.test(normalizedPlatform) && maxTouchPoints > 1);
  const browser: PushBrowserFamily = /firefox|fxios/.test(agent)
    ? "firefox"
    : /chrome|chromium|crios|edg|opr\//.test(agent)
      ? "chromium"
      : /safari/.test(agent)
        ? "safari"
        : "other";
  return { browser, ios, standalone };
}

export function currentPushClientEnvironment(): PushClientEnvironment {
  const standalone =
    window.matchMedia?.("(display-mode: standalone)").matches === true ||
    ("standalone" in navigator &&
      (navigator as Navigator & { standalone?: boolean }).standalone === true);
  return classifyPushClient(
    navigator.userAgent,
    navigator.platform,
    navigator.maxTouchPoints,
    standalone,
  );
}

export function pushDeviceName(platform: string, userAgent: string, standalone: boolean): string {
  const normalizedPlatform = Array.from(platform, (character) => {
    const point = character.codePointAt(0) ?? 0;
    return point <= 31 || point === 127 ? " " : character;
  })
    .join("")
    .replace(/\s+/g, " ")
    .trim();
  const agent = userAgent.toLowerCase();
  const fallback = /iphone/.test(agent)
    ? "iPhone"
    : /ipad/.test(agent)
      ? "iPad"
      : /android/.test(agent)
        ? "Android"
        : /macintosh|mac os x/.test(agent)
          ? "Mac"
          : /windows/.test(agent)
            ? "Windows"
            : /linux/.test(agent)
              ? "Linux"
              : "Browser";
  const base = normalizedPlatform || fallback;
  return `${base} · ${standalone ? "installed app" : "browser"}`.slice(0, 255);
}

export function currentPushDeviceName(): string {
  const environment = currentPushClientEnvironment();
  const platform =
    environment.ios && /^mac/i.test(navigator.platform) ? "iPad" : navigator.platform;
  return pushDeviceName(platform, navigator.userAgent, environment.standalone);
}

export function blockedPermissionHelp(environment: PushClientEnvironment): string {
  if (environment.ios) {
    return "Notifications are blocked for this Home Screen app. Open iOS/iPadOS Settings → Notifications, select this installed app, allow notifications, then reopen it.";
  }
  if (environment.browser === "safari") {
    return "Notifications are blocked. Open Safari → Settings → Websites → Notifications, set this site to Allow, then reload.";
  }
  if (environment.browser === "firefox") {
    return "Notifications are blocked. Open the site permissions beside the address bar, reset Notifications, then reload and allow the prompt.";
  }
  return "Notifications are blocked. Open this site's permissions beside the address bar, set Notifications to Allow, then reload.";
}

export function decodeApplicationServerKey(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.includes("=")) {
    throw new Error("The API returned an invalid VAPID public key.");
  }
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  let decoded: string;
  try {
    decoded = atob((value + padding).replace(/-/g, "+").replace(/_/g, "/"));
  } catch {
    throw new Error("The API returned an invalid VAPID public key.");
  }
  const bytes = new Uint8Array(new ArrayBuffer(decoded.length));
  for (let index = 0; index < decoded.length; index += 1) {
    bytes[index] = decoded.charCodeAt(index);
  }
  if (bytes.length !== 65 || bytes[0] !== 0x04) {
    throw new Error("The API returned an invalid VAPID public key.");
  }
  return bytes;
}

export function applicationServerKeyMatches(
  current: BufferSource | null,
  expected: Uint8Array,
): boolean {
  if (current == null) return false;
  const bytes = ArrayBuffer.isView(current)
    ? new Uint8Array(current.buffer, current.byteOffset, current.byteLength)
    : new Uint8Array(current);
  return (
    bytes.length === expected.length && bytes.every((value, index) => value === expected[index])
  );
}

export async function withPushTimeout<T>(
  operation: Promise<T>,
  timeoutMs: number,
  message: string,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), timeoutMs);
  });
  try {
    return await Promise.race([operation, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
