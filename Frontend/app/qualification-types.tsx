"use client";

export type Skill = {
  id: string;
  code: string;
  name: string;
  description?: string;
  active: boolean;
};

export type CertType = {
  id: string;
  code: string;
  name: string;
  description?: string;
  default_validity_days?: number;
  requires_file: boolean;
  active: boolean;
};

export type WorkProfile = {
  work_profile: { id: string; position: string; status: string };
  user_profile: { full_name: string };
};
