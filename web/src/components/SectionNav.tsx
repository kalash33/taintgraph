import { useEffect, useRef, useState } from "react";

export interface NavItem {
  id: string; // id of the section heading
  label: string;
}

/** A bar that stays on screen while the project page scrolls: where you are, and one click to any section. */
export default function SectionNav({ items }: { items: NavItem[] }) {
  const [active, setActive] = useState(items[0]?.id);
  const lockUntil = useRef(0); // after a click, keep that item lit while the page scrolls to it
  useEffect(() => {
    const els = items.map((i) => document.getElementById(i.id)).filter((e): e is HTMLElement => !!e);
    const io = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
        if (visible && Date.now() > lockUntil.current) setActive(visible.target.id);
      },
      { rootMargin: "-80px 0px -60% 0px" },
    );
    els.forEach((e) => io.observe(e));
    return () => io.disconnect();
  }, [items.map((i) => i.id).join("|")]);
  const go = (id: string) => {
    const el = document.getElementById(id);
    if (!el) return;
    lockUntil.current = Date.now() + 1200;
    window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY - 64, behavior: "smooth" });
    setActive(id);
  };
  return (
    <nav className="section-nav" aria-label="Sections of this project">
      <ol>
        {items.map((i, n) => (
          <li key={i.id}>
            <button type="button" className={active === i.id ? "is-active" : undefined} aria-current={active === i.id ? "true" : undefined} onClick={() => go(i.id)}>
              <span className="section-nav-n">{n + 1}</span>
              {i.label}
            </button>
          </li>
        ))}
      </ol>
    </nav>
  );
}
