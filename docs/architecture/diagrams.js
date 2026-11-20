(() => {
  const {components, calls, topics, stages} = architectureMap;
  const view = document.getElementById("view");
  const overview = document.getElementById("overview");
  const systemMap = document.getElementById("system-map");
  const diagram = document.getElementById("diagram");
  const selector = document.getElementById("selection");
  const sources = document.getElementById("sources");
  const svgNamespace = "http://www.w3.org/2000/svg";
  const groups = {client: "Веб и телеметрия", service: "Go-сервисы", system: "Хранилища и интеграции"};
  const defaults = {architecture: "overview", kafka: "tickets.events.v1"};
  let activeView;
  let activeSelection;
  let geometry;
  let focusSelector = false;

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  }

  function svgElement(tag, attributes) {
    const node = document.createElementNS(svgNamespace, tag);
    for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, value);
    return node;
  }

  function layout() {
    if (activeView === "architecture") {
      const [title, , description] = components[activeSelection];
      const first = calls.filter(({to}) => to === activeSelection)
        .map(({from, label, refs, note}) => ({id: from, label, refs, note}));
      const last = calls.filter(({from}) => from === activeSelection)
        .map(({to, label, refs, note}) => ({id: to, label, refs, note}));
      return {
        title, description, first, last,
        columns: ["Входящие вызовы", "Выбранный компонент", "Исходящие вызовы"],
        empty: ["Входящих связей на карте нет.", "Исходящих связей на карте нет."],
        note: "Стрелка идёт от клиента к получателю вызова. PostgreSQL и PostGIS обозначают типы отдельных БД сервисов.",
        hint: "Выберите компонент в списке или на схеме. Соседние блоки показывают прямые вызовы и подключения.",
      };
    }

    const topic = topics[activeSelection];
    return {
      title: activeSelection,
      description: stages[topic.stage],
      first: topic.writers.map(({service, ...details}) => ({id: service, ...details})),
      last: topic.readers.map(({service, ...details}) => ({id: service, ...details})),
      columns: ["Публикуют", "Топик Kafka", "Читают"],
      empty: ["Издателей на карте нет.", "Читателей среди штатных сервисов нет."],
      note: topic.note ?? "Под блоками читателей указаны группы по умолчанию. Список отражает код и конфигурации репозитория.",
      hint: "Выберите топик. Стрелки ведут от издателей к топику и от топика к читателям.",
      refs: topic.refs,
    };
  }

  function laneTitle(area, name, count) {
    const label = element("p", "lane-title", count === undefined ? name : name + " · " + count);
    label.dataset.area = area;
    return label;
  }

  function selectComponent(id) {
    focusSelector = true;
    window.location.hash = "architecture/" + id;
  }

  function node({title, label, area, id, ports = 1}) {
    const canSelect = Boolean(id) && activeView === "architecture";
    const block = element(canSelect ? "button" : "div", "node");
    if (canSelect) {
      block.type = "button";
      block.addEventListener("click", () => selectComponent(id));
    }
    if (area) {
      block.dataset.area = area;
      block.classList.add("focus-node");
      block.style.minHeight = Math.max(76, 22 + (ports - 1) * 9) + "px";
    }
    block.append(element("span", "node-name", title), element("span", "node-label", label));
    return block;
  }

  function lane(area, title, edges, empty) {
    const list = element(edges.length ? "ul" : "p", edges.length ? "neighbors" : "empty");
    list.dataset.area = area;
    if (edges.length) list.setAttribute("aria-label", title);
    else list.textContent = empty;
    const nodes = edges.map(({id, label}) => {
      const block = node({title: components[id][0], label, id});
      const item = element("li");
      item.append(block);
      list.append(item);
      return block;
    });
    return {list, nodes};
  }

  function routesLayer(root, arrowId) {
    const layer = svgElement("svg", {class: "routes", "aria-hidden": "true"});
    const defs = svgElement("defs", {});
    const marker = svgElement("marker", {
      id: arrowId, viewBox: "0 0 7 8", refX: 7, refY: 4,
      markerWidth: 7, markerHeight: 8, markerUnits: "userSpaceOnUse", orient: "auto",
    });
    marker.append(svgElement("path", {d: "M0 0 L7 4 L0 8 Z", fill: "currentColor"}));
    defs.append(marker);
    const connectorLayer = svgElement("g", {});
    layer.append(defs, connectorLayer);
    root.append(layer);
    return connectorLayer;
  }

  function renderDiagram(model) {
    const {title, description, columns, first, last, empty} = model;
    diagram.dataset.view = activeView;
    diagram.replaceChildren(
      laneTitle("left-title", columns[0], first.length),
      laneTitle("center-title", columns[1]),
      laneTitle("right-title", columns[2], last.length),
      laneTitle("in-title", columns[1]),
      laneTitle("out-title", columns[1]),
    );
    const left = lane("left", columns[0], first, empty[0]);
    const right = lane("right", columns[2], last, empty[1]);
    const center = node({title, label: description, area: "center", ports: Math.max(first.length, last.length)});
    const mobileIn = node({title, label: description, area: "in", ports: first.length});
    const mobileOut = node({title, label: description, area: "out", ports: last.length});
    diagram.append(left.list, center, right.list, mobileIn, mobileOut);
    geometry = {center, mobileIn, mobileOut, left: left.nodes, right: right.nodes, layer: routesLayer(diagram, "arrowhead")};
    drawRoutes();
    document.getElementById("diagram-note").textContent = model.note;
  }

  function drawRoutes() {
    if (!geometry) return;
    const {center, mobileIn, mobileOut, left, right, layer} = geometry;
    const board = diagram.getBoundingClientRect();
    const wide = center.getClientRects().length > 0;
    const incoming = (wide ? center : mobileIn).getBoundingClientRect();
    const outgoing = (wide ? center : mobileOut).getBoundingClientRect();

    // Keep central ports in the order of their neighbors. Equal horizontal
    // control points within each gutter keep the curves from crossing.
    function port(rect, index, length) {
      const span = Math.min((length - 1) * 9, rect.height - 22);
      const offset = length > 1 ? span * (index / (length - 1) - .5) : 0;
      return rect.top + rect.height / 2 + offset;
    }

    function connection(from, fromY, to, toY, direction) {
      const x1 = from.right - board.left;
      const x2 = to.left - board.left;
      const y1 = fromY - board.top;
      const y2 = toY - board.top;
      const bend = (x2 - x1) * .52;
      const d = ["M", x1, y1, "C", x1 + bend, y1, x2 - bend, y2, x2, y2].join(" ");
      return svgElement("path", {d, "data-edge": direction, "marker-end": "url(#arrowhead)"});
    }

    const inputs = left.map((block, index) => {
      const from = block.getBoundingClientRect();
      return connection(from, port(from, 0, 1), incoming, port(incoming, index, left.length), "in");
    });
    const outputs = right.map((block, index) => {
      const to = block.getBoundingClientRect();
      return connection(outgoing, port(outgoing, index, right.length), to, port(to, 0, 1), "out");
    });
    layer.replaceChildren(...inputs, ...outputs);
  }

  function evidenceItem(title, refs, note) {
    const item = element("li");
    const links = element("div", "ref-links");
    for (const ref of refs) {
      const link = element("a", null, ref.label);
      link.href = "../../" + ref.path;
      links.append(link);
    }
    item.append(element("strong", null, title));
    if (note) item.append(element("p", null, note));
    item.append(links);
    return item;
  }

  function renderEvidence({columns, first, last, refs}) {
    sources.replaceChildren();
    for (const [heading, edges] of [[columns[0], first], [columns[2], last]]) {
      if (!edges.length) continue;
      const section = element("section");
      const list = element("ul", "evidence-list");
      for (const {id, label, refs: references, note} of edges) {
        list.append(evidenceItem(components[id][0] + " · " + label, references, note));
      }
      section.append(element("h2", null, heading), list);
      sources.append(section);
    }
    if (refs?.length) {
      const list = element("ul", "evidence-list");
      list.append(evidenceItem("Создание топиков", refs));
      sources.append(list);
    }
  }

  function componentLink(id, label) {
    const link = element("a", label ? "node" : null);
    link.href = "#architecture/" + id;
    if (label) {
      link.append(element("span", "node-name", components[id][0]), element("span", "node-label", label));
    } else {
      link.textContent = components[id][0];
    }
    return link;
  }

  function populateOverview() {
    const callLabel = (from, to) => calls.find((call) => call.from === from && call.to === to).label;
    const entries = [
      ["browser", "Browser", "Веб-интерфейс"],
      ["simulator", "Simulator", "Телеметрия транспорта"],
      ["frontend", "Frontend", callLabel("Browser", "Frontend")],
      ["gateway", "Gateway", callLabel("Browser", "Gateway")],
      ["location", "Location", callLabel("Simulator", "Location")],
    ];
    const ingress = {};
    for (const [slot, id, label] of entries) {
      const link = componentLink(id, label);
      ingress[slot] = link;
      document.getElementById("overview-" + slot).append(link);
    }

    const gatewayServices = calls.filter(({from, label}) => from === "Gateway" && label === "gRPC")
      .map(({to}) => to);
    const infrastructure = [
      "PostgreSQL", "PostGIS", "RedisGateway", "RedisNotification", "RedisLocation",
      "ClickHouse", "S3", "Valhalla",
    ];
    for (const [list, ids] of [["service-links", gatewayServices], ["storage-links", infrastructure]]) {
      const items = ids.map((id) => {
        const item = element("li");
        item.append(componentLink(id));
        return item;
      });
      document.getElementById(list).append(...items);
    }

    const domainTopics = Object.values(topics).filter(({stage}) => stage === "domain");
    const publishers = new Set(domainTopics.flatMap(({writers}) => writers.map(({service}) => service)));
    const readers = new Set(domainTopics.flatMap((topic) => topic.readers.map(({service}) => service)));
    document.getElementById("kafka-publishers").textContent = "↓ Издатели · " + publishers.size;
    document.getElementById("kafka-readers").textContent = "↑ Читатели · " + readers.size;

    const providers = ["Nominatim", "Overpass", "MapTiles", "SMTP", "FCM"];
    const directCalls = calls.filter(({from, to}) =>
      providers.includes(to) || (from === "Browser" && to === "S3") || (from === "Frontend" && to === "Valhalla"));
    for (const {from, to, label} of directCalls) {
      const item = element("li", "integration-route");
      const arrow = element("span", "integration-arrow");
      arrow.setAttribute("aria-hidden", "true");
      item.append(componentLink(from, label), arrow, componentLink(to, components[to][2]));
      document.getElementById("integration-links").append(item);
    }

    const services = document.getElementById("overview-services");
    const storage = document.getElementById("overview-storage");
    const kafka = document.getElementById("overview-kafka");
    const layer = routesLayer(systemMap, "overview-arrow");

    function draw() {
      if (overview.hidden) return;
      const board = systemMap.getBoundingClientRect();
      const connections = [
        [ingress.browser, ingress.frontend, ingress.frontend, 0, false],
        [ingress.browser, ingress.gateway, ingress.gateway, 0, false],
        [ingress.simulator, ingress.location, ingress.location, 0, false],
        [ingress.gateway, services, ingress.gateway, 0, false],
        [services, storage, storage, 0, false],
        [services, kafka, kafka, -9, false],
        [kafka, services, kafka, 9, true],
      ];
      const paths = connections.map(([from, to, column, offset, up]) => {
        const source = from.getBoundingClientRect();
        const target = to.getBoundingClientRect();
        const anchor = column.getBoundingClientRect();
        const x = anchor.left + anchor.width / 2 + offset - board.left;
        const y1 = (up ? source.top : source.bottom) - board.top;
        const y2 = (up ? target.bottom : target.top) - board.top;
        const d = ["M", x, y1, "V", y2].join(" ");
        return svgElement("path", {d, "data-edge": "overview", "marker-end": "url(#overview-arrow)"});
      });
      layer.replaceChildren(...paths);
    }

    new ResizeObserver(draw).observe(systemMap);
    return draw;
  }

  function renderSelector() {
    const isArchitecture = activeView === "architecture";
    document.getElementById("selection-label").textContent = isArchitecture ? "Компонент" : "Топик Kafka";
    const optionGroups = isArchitecture ? groups : stages;
    const entries = isArchitecture
      ? Object.entries(components).map(([id, [title, type]]) => ({id, title, type}))
      : Object.entries(topics).map(([id, {stage}]) => ({id, title: id, type: stage}));
    const options = Object.entries(optionGroups).map(([type, title]) => {
      const group = element("optgroup");
      group.label = title;
      for (const entry of entries.filter((entry) => entry.type === type)) {
        const option = element("option", null, entry.title);
        option.value = entry.id;
        group.append(option);
      }
      return group;
    });
    if (isArchitecture) {
      const all = element("option", null, "Общая архитектура");
      all.value = "overview";
      options.unshift(all);
    }
    selector.replaceChildren(...options);
  }

  function render() {
    const [requestedView, requestedSelection] = window.location.hash.slice(1).split("/");
    const nextView = requestedView === "kafka" ? "kafka" : "architecture";
    const viewChanged = nextView !== activeView;
    const wasOverview = !overview.hidden;
    activeView = nextView;
    const available = activeView === "kafka" ? topics : components;
    activeSelection = Object.hasOwn(available, requestedSelection) ? requestedSelection : defaults[activeView];
    if (viewChanged) renderSelector();
    selector.value = activeSelection;
    for (const name of Object.keys(defaults)) {
      const link = document.getElementById(name + "-link");
      if (name === activeView) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
    const isOverview = activeView === "architecture" && activeSelection === "overview";
    overview.hidden = !isOverview;
    view.hidden = isOverview;
    if (viewChanged || isOverview !== wasOverview) window.scrollTo(0, 0);
    if (isOverview) {
      geometry = undefined;
      drawOverview();
      return;
    }
    const model = layout();
    document.getElementById("view-hint").textContent = model.hint;
    renderDiagram(model);
    renderEvidence(model);
    if (focusSelector || wasOverview) {
      focusSelector = false;
      selector.focus({preventScroll: wasOverview});
    }
  }

  selector.addEventListener("change", () => {
    window.location.hash = activeView + "/" + selector.value;
  });
  window.addEventListener("hashchange", render);
  new ResizeObserver(drawRoutes).observe(diagram);
  const drawOverview = populateOverview();
  render();
})();
