import { useQuery } from "@tanstack/react-query";

type FlagMap = Record<string, boolean>;

export function useFeatureFlags() {
  return useQuery<FlagMap>({
    queryKey: ["feature-flags-me"],
    queryFn: async () => {
      const res = await fetch("/api/feature-flags/me", { credentials: "include" });
      if (!res.ok) return {};
      return res.json();
    },
    staleTime: 30_000,
    retry: false,
  });
}

export function useFeatureFlag(name: string): boolean {
  const { data } = useFeatureFlags();
  return data?.[name] ?? false;
}
