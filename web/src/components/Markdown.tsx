import type { ReactNode } from "react";

/*
 Minimal, safe markdown: paragraphs, headings, nested lists, fenced code, **bold**, `code`, [links](http...).
 Never uses innerHTML; anything unrecognised is plain text.
*/

type ListItem = { text: string[]; children: ListBlock | null };
type ListBlock = { type: "list"; ordered: boolean; items: ListItem[] };
type Block =
  | { type: "p"; text: string }
  | { type: "h"; level: number; text: string }
  | { type: "code"; text: string }
  | ListBlock;

const LIST_RE = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/;

function indentOf(line: string): number {
  const m = line.match(/^(\s*)/);
  return m ? m[1].replace(/\t/g, "    ").length : 0;
}

function parseList(lines: string[], start: number, baseIndent: number): { block: ListBlock; next: number } {
  const first = lines[start].match(LIST_RE)!;
  const block: ListBlock = { type: "list", ordered: /\d/.test(first[2]), items: [] };
  let i = start;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) {
      // blank line: continue the list only if the next non-blank line is a list item at >= base indent
      let j = i + 1;
      while (j < lines.length && !lines[j].trim()) j++;
      if (j < lines.length && LIST_RE.test(lines[j]) && indentOf(lines[j]) >= baseIndent) {
        i = j;
        continue;
      }
      break;
    }
    const m = line.match(LIST_RE);
    const ind = indentOf(line);
    if (m && ind === baseIndent) {
      block.items.push({ text: [m[3]], children: null });
      i++;
    } else if (m && ind > baseIndent && block.items.length) {
      const sub = parseList(lines, i, ind);
      block.items[block.items.length - 1].children = sub.block;
      i = sub.next;
    } else if (!m && ind > baseIndent && block.items.length) {
      block.items[block.items.length - 1].text.push(line.trim());
      i++;
    } else if (m && ind < baseIndent) {
      break;
    } else {
      break;
    }
  }
  return { block, next: i };
}

export function parseBlocks(src: string): Block[] {
  const lines = src.replace(/\r\n?/g, "\n").split("\n");
  const blocks: Block[] = [];
  let para: string[] = [];
  const flushPara = () => {
    if (para.length) blocks.push({ type: "p", text: para.join("\n") });
    para = [];
  };
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^\s*```/.test(line)) {
      flushPara();
      const body: string[] = [];
      i++;
      while (i < lines.length && !/^\s*```/.test(lines[i])) body.push(lines[i++]);
      i++;
      blocks.push({ type: "code", text: body.join("\n") });
      continue;
    }
    if (!line.trim()) {
      flushPara();
      i++;
      continue;
    }
    const h = line.match(/^(#{1,6})\s+(.*)$/);
    if (h) {
      flushPara();
      blocks.push({ type: "h", level: h[1].length, text: h[2] });
      i++;
      continue;
    }
    if (LIST_RE.test(line) && (para.length === 0 || /^\s*([-*+]|\d+[.)])\s/.test(line))) {
      flushPara();
      const { block, next } = parseList(lines, i, indentOf(line));
      blocks.push(block);
      i = next;
      continue;
    }
    para.push(line);
    i++;
  }
  flushPara();
  return blocks;
}

const INLINE_RE = /(\*\*([^*]+)\*\*|`([^`]+)`|\[([^\]]+)\]\(([^)\s]+)\))/g;

export function Inline({ text }: { text: string }) {
  const out: ReactNode[] = [];
  let last = 0;
  let k = 0;
  for (const m of text.matchAll(INLINE_RE)) {
    const idx = m.index ?? 0;
    if (idx > last) out.push(text.slice(last, idx));
    if (m[2] !== undefined) out.push(<strong key={k++}>{m[2]}</strong>);
    else if (m[3] !== undefined) out.push(<code key={k++}>{m[3]}</code>);
    else if (m[4] !== undefined) {
      const url = m[5];
      if (/^https?:\/\//i.test(url)) {
        out.push(
          <a key={k++} href={url} target="_blank" rel="noopener noreferrer">
            {m[4]}
          </a>,
        );
      } else out.push(m[4]);
    }
    last = idx + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return <>{out}</>;
}

function Lines({ text }: { text: string }) {
  const parts = text.split("\n");
  return (
    <>
      {parts.map((p, i) => (
        <span key={i}>
          {i > 0 && <br />}
          <Inline text={p} />
        </span>
      ))}
    </>
  );
}

function List({ block }: { block: ListBlock }) {
  const items = block.items.map((it, i) => (
    <li key={i}>
      <Lines text={it.text.join("\n")} />
      {it.children && <List block={it.children} />}
    </li>
  ));
  return block.ordered ? <ol>{items}</ol> : <ul>{items}</ul>;
}

export default function Markdown({ source, headingBase = 3 }: { source: string; headingBase?: number }) {
  const blocks = parseBlocks(source);
  return (
    <div className="md">
      {blocks.map((b, i) => {
        if (b.type === "p")
          return (
            <p key={i}>
              <Lines text={b.text} />
            </p>
          );
        if (b.type === "code")
          return (
            <pre key={i} className="code-block">
              <code>{b.text}</code>
            </pre>
          );
        if (b.type === "h") {
          const level = Math.min(6, headingBase + b.level - 1);
          const Tag = `h${level}` as "h3";
          return (
            <Tag key={i} className="md-h">
              <Inline text={b.text} />
            </Tag>
          );
        }
        return <List key={i} block={b} />;
      })}
    </div>
  );
}
