import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, post } from "./client";
import type { Device, Inventory, RescanResult, SystemInfo } from "./types";

export const useSystem = () =>
  useQuery({ queryKey: ["system"], queryFn: () => api<SystemInfo>("/system"), refetchInterval: 15000 });

export const useInventory = () =>
  useQuery({ queryKey: ["devices"], queryFn: () => api<Inventory>("/devices"), refetchInterval: 10000 });

export const useDevice = (id: string | undefined) =>
  useQuery({
    queryKey: ["device", id],
    queryFn: () => api<Device>(`/devices/${encodeURIComponent(id!)}`),
    enabled: !!id,
    refetchInterval: 10000,
  });

export const useEvidence = (id: string | undefined) =>
  useQuery({
    queryKey: ["evidence", id],
    queryFn: () => api<Record<string, unknown>>(`/devices/${encodeURIComponent(id!)}/evidence`),
    enabled: !!id,
  });

export function useRescan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => post<RescanResult>("/discovery/rescan"),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["devices"] });
      qc.invalidateQueries({ queryKey: ["device"] });
    },
  });
}
