"use client";

export type Notice = (text: string) => void;

export type Category = { id: string; name: string; description?: string };

export type Department = { id: string; name: string };

export type ProtoTimestamp = { seconds?: number | string; nanos?: number };
