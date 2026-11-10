export interface Finding {
  id: string;
  severity: "high" | "medium" | "low";
  header: string;
  message: string;
}

export type Transport = (
  url: string,
) => Promise<{ status: number; headers: Array<[string, string]> }>;

export interface CheckOptions {
  url: string;
}

export interface IO {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  transport?: Transport;
}
