import { useEffect, useSyncExternalStore } from "react";
import { eventStream, type StreamState } from "./eventStream";

/** Keeps the shared WebSocket open while mounted and returns its state. */
export function useEventStream(): StreamState {
  useEffect(() => {
    eventStream.acquire();
    return () => eventStream.release();
  }, []);
  return useSyncExternalStore(eventStream.subscribe, eventStream.getSnapshot);
}
