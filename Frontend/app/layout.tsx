import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL || "http://localhost:3000"),
  title: "Город рядом — городские службы в одном окне",
  description: "Заявки жителей, диспетчеризация, маршруты бригад и контроль городской инфраструктуры.",
  openGraph: {
    title: "Город рядом",
    description: "Город слышит. Службы действуют.",
    images: [{ url: "/og.png", width: 1536, height: 1024, alt: "Город рядом — цифровые городские службы" }],
    locale: "ru_RU",
    type: "website",
  },
  twitter: { card: "summary_large_image", title: "Город рядом", description: "Город слышит. Службы действуют.", images: ["/og.png"] },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="ru">
      <body>{children}</body>
    </html>
  );
}
