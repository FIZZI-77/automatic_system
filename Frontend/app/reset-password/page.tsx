import { CityApp } from "../city-app";

export default function ResetPasswordPage({ searchParams }: { searchParams?: { token?: string } }) {
  return <CityApp initialAuthMode="reset" initialToken={searchParams?.token || ""} />;
}
