import { Header } from "@/components/landing/Header";
import { Hero } from "@/components/landing/Hero";
import { Features } from "@/components/landing/Features";
import { Pricing } from "@/components/landing/Pricing";
import { DemoSection } from "@/components/landing/DemoSection";
import { Footer } from "@/components/landing/Footer";

export default function Home() {
  return (
    <main className="min-h-screen bg-ebony-950">
      <Header />
      <Hero />
      <Features />
      <Pricing />
      <DemoSection />
      <Footer />
    </main>
  );
}
