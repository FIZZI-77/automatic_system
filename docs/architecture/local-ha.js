(() => {
  const { canvas, regions, cards, wires, dots, labels } = localHaTopology;
  const viewport = document.getElementById("viewport");
  const diagram = document.getElementById("diagram");
  const zoomIn = document.getElementById("zoom-in");
  const zoomOut = document.getElementById("zoom-out");
  const zoomLevel = document.getElementById("zoom-level");
  const svgNS = "http://www.w3.org/2000/svg";

  function svg(parent, name, attributes = {}, value) {
    const element = document.createElementNS(svgNS, name);
    for (const [key, item] of Object.entries(attributes)) {
      element.setAttribute(key, String(item));
    }
    if (value !== undefined) element.textContent = value;
    parent.append(element);
    return element;
  }

  function rectangle(parent, { x, y, w, h }, className, radius) {
    return svg(parent, "rect", { x, y, width: w, height: h, rx: radius, class: className });
  }

  function text(parent, x, y, value, className, anchor = "start", attributes = {}) {
    return svg(parent, "text", {
      x, y, class: className, "text-anchor": anchor, ...attributes,
    }, value);
  }

  function fitText(node, width, size) {
    const actual = node.getComputedTextLength();
    if (actual > width) node.style.fontSize = `${size * width / actual}px`;
  }

  const definitions = svg(diagram, "defs");
  const markerTypes = { request: "request", data: "data", event: "event", ops: "ops", optional: "neutral" };
  for (const [kind, color] of Object.entries(markerTypes)) {
    const marker = svg(definitions, "marker", {
      id: `tip-${kind}`, markerWidth: 10, markerHeight: 9, refX: 9.2, refY: 4.5,
      viewBox: "0 0 10 9", markerUnits: "userSpaceOnUse", orient: "auto-start-reverse",
    });
    svg(marker, "path", { d: "M 0 0 L 10 4.5 L 0 9 Z", fill: `var(--${color})` });
  }

  const zones = svg(diagram, "g", { id: "zones" });
  for (const region of regions) {
    rectangle(zones, region, `region region-${region.style}`, 16);
  }
  const relationships = svg(diagram, "g", { id: "relationships" });
  const components = svg(diagram, "g", { id: "components" });
  const annotations = svg(diagram, "g", { id: "annotations" });

  function toSegments(wire) {
    const segments = [];
    for (let i = 1; i < wire.points.length; i++) {
      const from = wire.points[i - 1];
      const to = wire.points[i];
      if (from[0] !== to[0] || from[1] !== to[1]) {
        segments.push({ from, to, horizontal: from[1] === to[1], breaks: [] });
      }
    }
    return { ...wire, segments };
  }

  function axisContains(a, b, point, padding) {
    return point > Math.min(a, b) + padding && point < Math.max(a, b) - padding;
  }

  // A gap in the underpassing wire distinguishes a crossing from a junction.
  function markCrossings(paths) {
    const horizontal = [];
    const vertical = [];
    for (const path of paths) {
      for (const segment of path.segments) {
        (segment.horizontal ? horizontal : vertical).push({ path, segment });
      }
    }
    for (const h of horizontal) {
      for (const v of vertical) {
        if (h.path === v.path || (h.path.net && h.path.net === v.path.net)) continue;
        const x = v.segment.from[0];
        const y = h.segment.from[1];
        if (axisContains(h.segment.from[0], h.segment.to[0], x, 6)
          && axisContains(v.segment.from[1], v.segment.to[1], y, 4)) {
          h.segment.breaks.push(x);
        }
      }
    }
  }

  function wirePath(segments) {
    const [x, y] = segments[0].from;
    const commands = [`M ${x} ${y}`];
    for (const { from, to, breaks } of segments) {
      const ascending = from[0] < to[0];
      const sign = ascending ? 1 : -1;
      let last = from[0];
      const gaps = [...new Set(breaks)].sort((a, b) => sign * (a - b));
      for (const gap of gaps) {
        const entry = gap - sign * 5;
        const exit = gap + sign * 5;
        if (sign * (entry - last) > 0) commands.push(`L ${entry} ${from[1]}`);
        if (sign * (exit - last) > 0) {
          commands.push(`M ${exit} ${from[1]}`);
          last = exit;
        }
      }
      commands.push(`L ${to[0]} ${to[1]}`);
    }
    return commands.join(" ");
  }

  function drawWires() {
    const paths = wires.map(toSegments).filter(({ segments }) => segments.length);
    markCrossings(paths);
    for (const path of paths) {
      const group = svg(relationships, "g", { "data-edge": path.title });
      svg(group, "title", {}, path.title);
      const edge = svg(group, "path", {
        d: wirePath(path.segments), class: `wire ${path.kind}`,
      });
      // The visible polyline may have multiple SVG subpaths at crossings.
      // Keep markers on the physical endpoints only.
      const first = path.segments[0];
      const last = path.segments.at(-1);
      for (const [direction, segment] of [["start", first], ["end", last]]) {
        if (!path[direction]) continue;
        const tip = direction === "end" ? segment.to : segment.from;
        const other = direction === "end" ? segment.from : segment.to;
        const length = Math.min(12, Math.hypot(other[0] - tip[0], other[1] - tip[1]));
        const near = tip.map((value, i) => value + Math.sign(other[i] - value) * length);
        svg(group, "path", {
          d: `M ${near.join(" ")} L ${tip.join(" ")}`, class: edge.getAttribute("class"),
          "marker-end": `url(#tip-${path.kind})`,
        });
      }
    }
    for (const { kind, point: [cx, cy] } of dots) {
      svg(relationships, "circle", { cx, cy, r: 3.5, class: `dot ${kind}` });
    }
  }

  function drawCard(node) {
    const { id, x, y, w, h, title, endpoint, pods, compact, split, address } = node;
    const group = svg(components, "g", { "data-card": id, "aria-label": title });
    svg(group, "title", {}, [title, endpoint, ...((pods || []).map((pod) => pod.name))].filter(Boolean).join(" · "));
    rectangle(group, node, `card${node.optional ? " optional" : ""}`, 10);
    text(group, x + 13, y + (h < 78 ? 26 : 28), title, `card-heading${compact ? " compact" : ""}`);
    if (endpoint) {
      fitText(text(group, x + 13, y + (h < 78 ? 47 : 49), endpoint, "endpoint"), w - 24, 14);
    }
    if (pods) {
      const podTop = y + (endpoint ? (split ? 70 : 58) : 31);
      const podHeight = Math.min(pods.some(({ detail }) => detail) ? 44 : 35,
        y + h - podTop - (address ? 30 : 10));
      const gap = 7;
      const podWidth = (w - 24 - (pods.length - 1) * gap) / pods.length;
      const centres = [];
      for (const [index, pod] of pods.entries()) {
        const podX = x + 12 + index * (podWidth + gap);
        const center = podX + podWidth / 2;
        centres.push(center);
        const replica = svg(group, "g", { "data-replica": pod.workload || id });
        rectangle(replica, { x: podX, y: podTop, w: podWidth, h: podHeight }, "replica", 6);
        const fontSize = node.podFont || 15;
        const nameY = pod.detail ? podTop + Math.min(16, podHeight / 2 - 1) : podTop + podHeight / 2 + 5;
        const podName = text(replica, center, nameY, pod.name, "replica-id", "middle", {
          style: `font-size:${fontSize}px`,
        });
        fitText(podName, podWidth - 10, fontSize);
        if (pod.detail) {
          fitText(text(replica, center, podTop + podHeight - 7, pod.detail, "replica-detail", "middle"),
            podWidth - 10, 11);
        }
      }
      if (split) {
        const neck = podTop - 8;
        let path = `M ${x + w / 2} ${neck - 5} V ${neck}`;
        path += ` M ${centres[0]} ${neck} H ${centres.at(-1)}`;
        for (const center of centres) path += ` M ${center} ${neck} V ${podTop}`;
        svg(group, "path", { d: path, class: "pod-wire" });
      }
    }
    if (address) {
      const pill = text(group, x + w / 2, y + h - 9, address, "address", "middle");
      pill.setAttribute("data-address", address);
    }
    node.lines?.forEach((line, index) => {
      text(group, x + 13, y + 77 + index * 24, line, "diagram-note");
    });
  }

  drawWires();
  cards.forEach(drawCard);
  for (const region of regions) {
    text(annotations, region.x + 24, region.y + 43, region.title, "region-heading");
    if (region.subtitle) {
      text(annotations, region.x + 24, region.y + 72, region.subtitle, "region-subtitle");
    }
  }
  for (const item of labels) {
    text(annotations, item.x, item.y, item.value, `edge-label ${item.kind}`, item.align);
  }

  const camera = { x: 0, y: 0, scale: 1 };
  const visible = { width: 0, height: 0 };
  const maxScale = 3.5;
  let minimum = .1;
  let fitted = true;

  function update() {
    diagram.setAttribute("viewBox", [
      camera.x, camera.y, visible.width / camera.scale, visible.height / camera.scale,
    ].join(" "));
    const percentage = `${Math.round(camera.scale * 100)}%`;
    if (zoomLevel.value !== percentage) zoomLevel.value = percentage;
    zoomOut.disabled = camera.scale <= minimum + .0001;
    zoomIn.disabled = camera.scale >= maxScale - .0001;
  }

  function fit() {
    camera.scale = Math.min(Math.max(visible.width - 22, 1) / canvas.width,
      Math.max(visible.height - 22, 1) / canvas.height);
    minimum = Math.max(.04, camera.scale * .68);
    camera.x = (canvas.width - visible.width / camera.scale) / 2;
    camera.y = (canvas.height - visible.height / camera.scale) / 2;
    fitted = true;
    update();
  }

  function resize() {
    const previous = { ...visible };
    visible.width = viewport.clientWidth;
    visible.height = viewport.clientHeight;
    if (!visible.width || !visible.height) return;
    if (fitted || !previous.width) {
      fit();
    } else {
      minimum = Math.max(.04, Math.min(visible.width / canvas.width, visible.height / canvas.height) * .68);
      camera.x += (previous.width - visible.width) / (2 * camera.scale);
      camera.y += (previous.height - visible.height) / (2 * camera.scale);
      update();
    }
  }

  function setScale(scale, screenX = visible.width / 2, screenY = visible.height / 2) {
    const previous = camera.scale;
    camera.scale = Math.max(minimum, Math.min(scale, maxScale));
    camera.x += screenX * (1 / previous - 1 / camera.scale);
    camera.y += screenY * (1 / previous - 1 / camera.scale);
    fitted = false;
    update();
  }

  function pan(pixelX, pixelY) {
    camera.x -= pixelX / camera.scale;
    camera.y -= pixelY / camera.scale;
    fitted = false;
    update();
  }

  function localPoint(event) {
    const { left, top } = viewport.getBoundingClientRect();
    return { x: event.clientX - left, y: event.clientY - top };
  }

  zoomIn.addEventListener("click", () => setScale(camera.scale * 1.25));
  zoomOut.addEventListener("click", () => setScale(camera.scale / 1.25));
  document.getElementById("actual-size").addEventListener("click", () => setScale(1));
  document.getElementById("fit").addEventListener("click", fit);
  viewport.addEventListener("wheel", (event) => {
    event.preventDefault();
    const point = localPoint(event);
    const delta = event.deltaY * (event.deltaMode === 1 ? 16 : event.deltaMode === 2 ? visible.height : 1);
    setScale(camera.scale * Math.exp(-delta * .0018), point.x, point.y);
  }, { passive: false });

  const pointers = new Map();
  const midpoint = (a, b) => ({ x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 });
  const distance = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);
  viewport.addEventListener("pointerdown", (event) => {
    if (event.button !== 0 || pointers.size >= 2) return;
    viewport.focus({ preventScroll: true });
    viewport.setPointerCapture(event.pointerId);
    pointers.set(event.pointerId, localPoint(event));
    viewport.classList.add("is-dragging");
  });
  viewport.addEventListener("pointermove", (event) => {
    if (!pointers.has(event.pointerId)) return;
    const before = [...pointers.values()];
    const previous = pointers.get(event.pointerId);
    const point = localPoint(event);
    pointers.set(event.pointerId, point);
    if (before.length === 1) {
      pan(point.x - previous.x, point.y - previous.y);
      return;
    }
    const after = [...pointers.values()];
    const start = midpoint(...before);
    const end = midpoint(...after);
    const factor = distance(...after) / Math.max(distance(...before), 1);
    setScale(camera.scale * factor, start.x, start.y);
    pan(end.x - start.x, end.y - start.y);
  });
  function release(event) {
    pointers.delete(event.pointerId);
    if (!pointers.size) viewport.classList.remove("is-dragging");
  }
  viewport.addEventListener("pointerup", release);
  viewport.addEventListener("pointercancel", release);
  viewport.addEventListener("lostpointercapture", release);
  viewport.addEventListener("keydown", (event) => {
    const offsets = { ArrowLeft: [70, 0], ArrowRight: [-70, 0], ArrowUp: [0, 70], ArrowDown: [0, -70] };
    if (offsets[event.key]) pan(...offsets[event.key]);
    else if (event.key === "+" || event.key === "=") setScale(camera.scale * 1.25);
    else if (event.key === "-") setScale(camera.scale / 1.25);
    else if (event.key === "0") fit();
    else if (event.key === "1") setScale(1);
    else return;
    event.preventDefault();
  });
  new ResizeObserver(resize).observe(viewport);
  resize();
})();
