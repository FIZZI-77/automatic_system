import { CityApp } from "../city-app";

export default function VerifyEmailPage({ searchParams }: { searchParams?: { token?: string } }) {
  return <CityApp initialAuthMode="verify" initialToken={searchParams?.token || ""} />;
}
