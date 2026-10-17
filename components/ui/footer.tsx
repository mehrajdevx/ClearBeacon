import { Footerdemo } from "@/components/ui/footer-section";
import type { Theme } from "@/frontend/theme";

interface FooterProps {
  theme: Theme;
  onToggleTheme: () => void;
}

function Footer(props: FooterProps) {
  return (
    <div className="block">
      <Footerdemo {...props} />
    </div>
  );
}

export { Footer };
