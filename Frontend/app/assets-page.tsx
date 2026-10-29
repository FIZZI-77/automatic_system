"use client";

/* eslint-disable react-hooks/set-state-in-effect */

import { FormEvent, useCallback, useEffect, useState } from "react";

import { api, config, Session } from "./api";

import { ReadableDetails } from "./readable-details";

import {
  type Dict,
  text,
  timestamp,
  type Notice,
  enumLabel,
  Empty,
  Modal,
} from "./admin-shared";

const predictionRiskNames: Record<string, string> = {
  UNKNOWN: "Не определён",
  LOW: "Низкий",
  MEDIUM: "Средний",
  HIGH: "Высокий",
  CRITICAL: "Критический",
};

const predictionActions: Record<string, string> = {
  "normal scheduled maintenance": "Продолжать плановое обслуживание",
  "shorten inspection interval": "Сократить интервал между осмотрами",
  "priority inspection and preventive repair":
    "Провести приоритетный осмотр и профилактический ремонт",
  "immediate inspection and replacement planning":
    "Немедленно осмотреть объект и запланировать замену",
};

const predictionFactors: Record<string, string> = {
  "service life is nearly exhausted": "Срок службы близок к окончанию",
  "repeated failures within 90 days":
    "За последние 90 дней были повторные неисправности",
  "inspection is overdue": "Плановый осмотр просрочен",
  "poor latest inspection condition":
    "Последний осмотр показал неудовлетворительное состояние",
};

function predictionValue(source: Dict, key: string) {
  const prediction = (
    source.prediction && typeof source.prediction === "object"
      ? source.prediction
      : source
  ) as Dict;
  return prediction[key];
}

function AssetPredictionCard({ data }: { data: Dict }) {
  const rawLevel = predictionValue(data, "risk_level"),
    level =
      typeof rawLevel === "number"
        ? riskLevels[rawLevel] || "UNKNOWN"
        : text(rawLevel, "UNKNOWN").replace("RISK_LEVEL_", "");
  const score = Math.max(
      0,
      Math.min(100, Number(predictionValue(data, "risk_score") || 0)),
    ),
    probability = Math.max(
      0,
      Math.min(
        100,
        Number(predictionValue(data, "failure_probability_90d") || 0),
      ),
    );
  const factors = Array.isArray(predictionValue(data, "factors"))
    ? (predictionValue(data, "factors") as unknown[])
    : [];
  const calculated = predictionValue(data, "calculated_at"),
    calculatedText = calculated
      ? timestamp(
          typeof calculated === "object" &&
            calculated !== null &&
            "seconds" in calculated
            ? (calculated as { seconds: unknown }).seconds
            : calculated,
        )
      : "—";
  return (
    <section className={`asset-prediction ${level.toLowerCase()}`}>
      <div className="prediction-heading">
        <div>
          <span>Прогноз состояния</span>
          <h3>{predictionRiskNames[level] || level} риск</h3>
        </div>
        <strong>
          {Math.round(probability)}
          <small>%</small>
        </strong>
      </div>
      <p>Вероятность неисправности в течение ближайших 90 дней</p>
      <div className="prediction-meter">
        <i style={{ width: `${probability}%` }} />
      </div>
      <div className="prediction-facts">
        <div>
          <span>Оценка риска</span>
          <b>{score.toFixed(1)} из 100</b>
        </div>
        <div>
          <span>Рассчитано</span>
          <b>{calculatedText}</b>
        </div>
      </div>
      <div className="prediction-recommendation">
        <span>Что рекомендуется сделать</span>
        <b>
          {predictionActions[
            text(predictionValue(data, "recommended_action"))
          ] ||
            text(
              predictionValue(data, "recommended_action"),
              "Продолжать наблюдение",
            )}
        </b>
      </div>
      <div className="prediction-factors">
        <span>Что повлияло на прогноз</span>
        {factors.length ? (
          <ul>
            {factors.map((factor, index) => (
              <li key={index}>
                {predictionFactors[text(factor)] || text(factor)}
              </li>
            ))}
          </ul>
        ) : (
          <p>Существенных факторов риска не обнаружено.</p>
        )}
      </div>
    </section>
  );
}

const assetStatuses = [
  "UNKNOWN",
  "PLANNED",
  "INSTALLED",
  "ACTIVE",
  "DAMAGED",
  "UNDER_REPAIR",
  "NEEDS_REPLACEMENT",
  "REPLACED",
  "DECOMMISSIONED",
];

const riskLevels = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

type Asset = {
  id: string;
  department_id: string;
  type: string;
  name: string;
  address?: string;
  district?: string;
  status?: string;
  risk_level?: string;
  criticality?: number;
  geometry_geo_json?: string;
};

export function AssetsPage({
  session,
  onNotice,
}: {
  session: Session;
  onNotice: Notice;
}) {
  const demo = session.accessToken === "demo";
  const [assets, setAssets] = useState<Asset[]>([]);
  const [selected, setSelected] = useState<Asset>();
  const [modal, setModal] = useState<string>();
  const [details, setDetails] = useState<Dict>();
  const [detailsKind, setDetailsKind] = useState<"prediction" | "other">(
    "other",
  );
  const [filter, setFilter] = useState("");
  const [assetFilters, setAssetFilters] = useState({
    department_id: "",
    type: "",
    district: "",
    status: "",
    risk_level: "",
  });
  const load = useCallback(async () => {
    if (demo) {
      setAssets([
        {
          id: "asset-demo-1",
          department_id: "dep-roads",
          type: "STREET_LIGHT",
          name: "Опора освещения №124",
          address: "Тверская улица, 12",
          district: "Тверской",
          status: "ACTIVE",
          risk_level: "LOW",
          criticality: 0.35,
        },
        {
          id: "asset-demo-2",
          department_id: "dep-utilities",
          type: "FIRE_HYDRANT",
          name: "Пожарный гидрант №77",
          address: "Большая Дмитровка, 18",
          district: "Тверской",
          status: "DEGRADED",
          risk_level: "HIGH",
          criticality: 0.9,
        },
        {
          id: "asset-demo-3",
          department_id: "dep-roads",
          type: "ROAD_SIGN",
          name: "Дорожный знак 3.27",
          address: "Страстной бульвар, 6",
          district: "Тверской",
          status: "UNDER_REPAIR",
          risk_level: "MEDIUM",
          criticality: 0.55,
        },
      ]);
      return;
    }
    try {
      const result = await api<{
        assets: (Asset & { status?: unknown; risk_level?: unknown })[];
      }>(
        config.endpoints.assetsList,
        {
          limit: 200,
          offset: 0,
          ...Object.fromEntries(
            Object.entries(assetFilters).filter(([, value]) => value),
          ),
        },
        "POST",
        session.accessToken,
      );
      setAssets(
        (result.assets || []).map((item) => ({
          ...item,
          status: enumLabel(item.status, assetStatuses),
          risk_level: enumLabel(item.risk_level, riskLevels),
        })),
      );
    } catch (error) {
      onNotice(
        error instanceof Error
          ? error.message
          : "Не удалось загрузить реестр инфраструктуры",
      );
    }
  }, [assetFilters, demo, onNotice, session.accessToken]);
  useEffect(() => {
    void load();
  }, [load]);

  async function create(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const d = new FormData(e.currentTarget);
    const payload = {
      department_id: String(d.get("department_id")),
      type: String(d.get("type")),
      name: String(d.get("name")),
      address: String(d.get("address")),
      district: String(d.get("district")),
      geometry_geo_json: JSON.stringify({
        type: "Point",
        coordinates: [Number(d.get("longitude")), Number(d.get("latitude"))],
      }),
      criticality: Number(d.get("criticality")),
      inspection_interval_days: Number(d.get("inspection_interval_days")),
    };
    if (!demo)
      await api(
        config.endpoints.assetsCreate,
        payload,
        "POST",
        session.accessToken,
      );
    setModal(undefined);
    await load();
    onNotice("Объект инфраструктуры сохранён");
  }
  async function updateAsset(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!selected) return;
    const d = new FormData(e.currentTarget),
      payload = {
        asset_id: selected.id,
        name: String(d.get("name")),
        address: String(d.get("address")),
        contractor: String(d.get("contractor")),
        criticality: Number(d.get("criticality")),
      };
    if (!demo)
      await api(
        config.endpoints.assetsUpdate,
        payload,
        "POST",
        session.accessToken,
      );
    const next = {
      ...selected,
      name: payload.name,
      address: payload.address,
      criticality: payload.criticality,
    };
    setSelected(next);
    setAssets((items) =>
      items.map((item) => (item.id === next.id ? next : item)),
    );
    setModal(undefined);
    onNotice("Паспорт объекта обновлён");
  }
  async function changeStatus(status: string) {
    if (!selected) return;
    if (!demo)
      await api(
        config.endpoints.assetsStatus,
        { asset_id: selected.id, status, reason: "Изменено из реестра" },
        "POST",
        session.accessToken,
      );
    setAssets((items) =>
      items.map((item) =>
        item.id === selected.id ? { ...item, status } : item,
      ),
    );
    setSelected({ ...selected, status });
    onNotice("Статус объекта обновлён");
  }
  async function operation(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!selected || !modal) return;
    const d = new FormData(e.currentTarget);
    let endpoint = "",
      payload: Dict = { asset_id: selected.id };
    if (modal === "incident") {
      endpoint = config.endpoints.assetsIncident;
      payload = {
        ...payload,
        failure_type: String(d.get("kind")),
        description: String(d.get("description")),
        source: "WEB",
        priority: String(d.get("priority")),
      };
    }
    if (modal === "inspection") {
      endpoint = config.endpoints.assetsInspection;
      payload = {
        ...payload,
        kind: String(d.get("kind")),
        result: String(d.get("description")),
        recommendation: String(d.get("recommendation")),
        defect_found: d.get("defect") !== null,
        condition_score: Number(d.get("score")),
      };
    }
    if (modal === "repair") {
      endpoint = config.endpoints.assetsRepair;
      payload = {
        ...payload,
        description: String(d.get("description")),
        replaced_components: String(d.get("recommendation")),
        duration_minutes: Number(d.get("duration")),
      };
    }
    if (modal === "maintenance") {
      endpoint = config.endpoints.assetsMaintenanceCreate;
      payload = {
        ...payload,
        kind: String(d.get("kind")),
        interval_days: Number(d.get("duration")),
        next_due_at: new Date(String(d.get("date"))).toISOString(),
      };
    }
    setDetailsKind("other");
    if (!demo)
      setDetails(
        await api<Dict>(endpoint, payload, "POST", session.accessToken),
      );
    setModal(undefined);
    onNotice("Операция по объекту зарегистрирована");
  }
  async function predict() {
    if (!selected) return;
    setDetailsKind("prediction");
    setDetails(
      demo
        ? {
            prediction: {
              asset_id: selected.id,
              risk_score: 28.4,
              risk_level: "LOW",
              failure_probability_90d: 18.7,
              factors: ["inspection is overdue"],
              recommended_action: "normal scheduled maintenance",
              calculated_at: { seconds: Math.floor(Date.now() / 1000) },
            },
          }
        : await api<Dict>(
            config.endpoints.assetsPrediction,
            { asset_id: selected.id },
            "POST",
            session.accessToken,
          ),
    );
  }
  async function recalculate() {
    const result = demo
      ? { updated: 1 }
      : await api<Dict>(
          config.endpoints.assetsRisksRecalculate,
          {},
          "POST",
          session.accessToken,
        );
    setDetailsKind("other");
    setDetails(result);
    onNotice("Риски пересчитаны");
  }
  async function nearby() {
    const result = demo
      ? { assets }
      : await api<Dict>(
          config.endpoints.assetsNearby,
          {
            latitude: 55.751244,
            longitude: 37.618423,
            radius_meters: 5000,
            limit: 100,
          },
          "POST",
          session.accessToken,
        );
    setDetailsKind("other");
    setDetails(result);
    onNotice("Найдены объекты в радиусе 5 км от центра Москвы");
  }
  async function due() {
    const result = demo
      ? { plans: [] }
      : await api<Dict>(
          config.endpoints.assetsMaintenanceDue,
          {
            due_before: new Date(Date.now() + 30 * 86400000).toISOString(),
            limit: 100,
            offset: 0,
          },
          "POST",
          session.accessToken,
        );
    setDetailsKind("other");
    setDetails(result);
    onNotice("Загружен план обслуживания на 30 дней");
  }
  async function summary() {
    const result = demo
      ? { total: assets.length }
      : await api<Dict>(
          config.endpoints.analyticsAssetsSummary,
          { filter: {} },
          "POST",
          session.accessToken,
        );
    setDetailsKind("other");
    setDetails(result);
    onNotice("Сводка Asset Analytics загружена");
  }
  const visible = assets.filter((item) =>
    `${item.id} ${item.name} ${item.type} ${item.address} ${item.department_id || ""}`
      .toLocaleLowerCase("ru-RU")
      .includes(filter.trim().toLocaleLowerCase("ru-RU")),
  );
  return (
    <section className="ops-page asset-page">
      <div className="ops-head">
        <div>
          <span className="eyebrow">Asset Service</span>
          <h2>Реестр городской инфраструктуры</h2>
          <p>Паспорта объектов, состояние, осмотры, ремонты и обслуживание.</p>
        </div>
        <div>
          <button className="ghost" onClick={() => void nearby()}>
            Рядом
          </button>
          <button className="ghost" onClick={() => void due()}>
            План ТО
          </button>
          <button className="ghost" onClick={() => void summary()}>
            Сводка
          </button>
          <button className="ghost" onClick={recalculate}>
            Риски
          </button>
          <button className="primary" onClick={() => setModal("create")}>
            + Объект
          </button>
        </div>
      </div>
      <div className="service-filters">
        <label>
          Департамент
          <input
            value={assetFilters.department_id}
            onChange={(e) =>
              setAssetFilters((v) => ({ ...v, department_id: e.target.value }))
            }
            placeholder="UUID департамента"
          />
        </label>
        <label>
          Тип
          <input
            value={assetFilters.type}
            onChange={(e) =>
              setAssetFilters((v) => ({ ...v, type: e.target.value }))
            }
            placeholder="STREET_LIGHT"
          />
        </label>
        <label>
          Район
          <input
            value={assetFilters.district}
            onChange={(e) =>
              setAssetFilters((v) => ({ ...v, district: e.target.value }))
            }
            placeholder="Тверской"
          />
        </label>
        <label>
          Состояние
          <select
            value={assetFilters.status}
            onChange={(e) =>
              setAssetFilters((v) => ({ ...v, status: e.target.value }))
            }
          >
            <option value="">Все</option>
            {assetStatuses.slice(1).map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
        <label>
          Риск
          <select
            value={assetFilters.risk_level}
            onChange={(e) =>
              setAssetFilters((v) => ({ ...v, risk_level: e.target.value }))
            }
          >
            <option value="">Все</option>
            {riskLevels.slice(1).map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
        <button
          onClick={() =>
            setAssetFilters({
              department_id: "",
              type: "",
              district: "",
              status: "",
              risk_level: "",
            })
          }
        >
          Сбросить
        </button>
      </div>
      <div className="ops-toolbar">
        <input
          placeholder="UUID, название, тип или адрес"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <b>{visible.length} объектов</b>
      </div>
      <div className={`ops-layout ${selected ? "selected" : ""}`}>
        <div className="ops-grid">
          {visible.map((item) => (
            <button
              key={item.id}
              className={selected?.id === item.id ? "selected" : ""}
              onClick={() => {
                setSelected(item);
                setDetails(undefined);
              }}
            >
              <span
                className={`ops-state ${(item.status || "unknown").toLowerCase()}`}
              >
                ● {item.status || "UNKNOWN"}
              </span>
              <h3>{item.name}</h3>
              <p>
                {item.type} · {item.district || "округ не задан"}
              </p>
              <small>{item.address || "Адрес не задан"}</small>
              <div>
                <b>Риск: {item.risk_level || "—"}</b>
                <span>
                  Критичность {Math.round((item.criticality || 0) * 100)}%
                </span>
              </div>
            </button>
          ))}
        </div>
        {!visible.length && <Empty>В реестре пока нет объектов.</Empty>}
        {selected && (
          <aside className="ops-detail asset-detail">
            <button
              className="detail-close"
              onClick={() => setSelected(undefined)}
            >
              ×
            </button>
            <span className="eyebrow">Паспорт объекта</span>
            <h2>{selected.name}</h2>
            <p>{selected.address}</p>
            <dl>
              <div>
                <dt>ID</dt>
                <dd>{selected.id}</dd>
              </div>
              <div>
                <dt>Тип</dt>
                <dd>{selected.type}</dd>
              </div>
              <div>
                <dt>Район</dt>
                <dd>{selected.district || "—"}</dd>
              </div>
              <div>
                <dt>Риск</dt>
                <dd>
                  {predictionRiskNames[selected.risk_level || ""] ||
                    selected.risk_level ||
                    "—"}
                </dd>
              </div>
            </dl>
            <label>
              Состояние
              <select
                value={selected.status || "ACTIVE"}
                onChange={(e) => void changeStatus(e.target.value)}
              >
                <option value="ACTIVE">Активен</option>
                <option value="DEGRADED">Ухудшено</option>
                <option value="FAILED">Неисправен</option>
                <option value="UNDER_REPAIR">На ремонте</option>
                <option value="DECOMMISSIONED">Выведен</option>
              </select>
            </label>
            <div className="ops-actions">
              <button onClick={() => setModal("edit")}>Изменить</button>
              <button onClick={() => setModal("incident")}>Инцидент</button>
              <button onClick={() => setModal("inspection")}>Осмотр</button>
              <button onClick={() => setModal("repair")}>Ремонт</button>
              <button onClick={() => setModal("maintenance")}>ТО</button>
              <button onClick={() => void predict()}>Прогноз</button>
            </div>
            {details &&
              (detailsKind === "prediction" ? (
                <AssetPredictionCard data={details} />
              ) : (
                <ReadableDetails data={details} />
              ))}
          </aside>
        )}
      </div>
      {modal === "create" && (
        <Modal
          title="Новый объект инфраструктуры"
          onClose={() => setModal(undefined)}
        >
          <form onSubmit={create} className="ops-form">
            <label>
              Название
              <input name="name" required />
            </label>
            <div>
              <label>
                Департамент ID
                <input name="department_id" required />
              </label>
              <label>
                Тип
                <input name="type" defaultValue="STREET_LIGHT" required />
              </label>
            </div>
            <label>
              Адрес
              <input name="address" />
            </label>
            <label>
              Район
              <input name="district" />
            </label>
            <div>
              <label>
                Широта
                <input
                  name="latitude"
                  type="number"
                  step="any"
                  defaultValue="55.751244"
                  required
                />
              </label>
              <label>
                Долгота
                <input
                  name="longitude"
                  type="number"
                  step="any"
                  defaultValue="37.618423"
                  required
                />
              </label>
            </div>
            <div>
              <label>
                Критичность
                <input
                  name="criticality"
                  type="number"
                  min="0"
                  max="1"
                  step="0.05"
                  defaultValue="0.5"
                />
              </label>
              <label>
                Осмотр, дней
                <input
                  name="inspection_interval_days"
                  type="number"
                  defaultValue="30"
                />
              </label>
            </div>
            <button className="primary">Сохранить объект</button>
          </form>
        </Modal>
      )}
      {selected && modal === "edit" && (
        <Modal
          title="Изменить паспорт объекта"
          onClose={() => setModal(undefined)}
        >
          <form onSubmit={updateAsset} className="ops-form">
            <label>
              Название
              <input name="name" defaultValue={selected.name} required />
            </label>
            <label>
              Адрес
              <input name="address" defaultValue={selected.address} />
            </label>
            <label>
              Подрядчик
              <input name="contractor" />
            </label>
            <label>
              Критичность
              <input
                name="criticality"
                type="number"
                min="0"
                max="1"
                step="0.05"
                defaultValue={selected.criticality}
              />
            </label>
            <button className="primary">Сохранить</button>
          </form>
        </Modal>
      )}
      {selected && modal && !["create", "edit"].includes(modal) && (
        <Modal
          title={
            {
              incident: "Зарегистрировать инцидент",
              inspection: "Результат осмотра",
              repair: "Завершить ремонт",
              maintenance: "План обслуживания",
            }[modal] || "Операция"
          }
          onClose={() => setModal(undefined)}
        >
          <form onSubmit={operation} className="ops-form">
            <label>
              Вид работ / события
              <input name="kind" required />
            </label>
            {modal !== "maintenance" && (
              <label>
                Описание
                <textarea name="description" required rows={4} />
              </label>
            )}
            {modal === "incident" && (
              <label>
                Приоритет
                <select name="priority">
                  <option>MEDIUM</option>
                  <option>HIGH</option>
                  <option>EMERGENCY</option>
                </select>
              </label>
            )}
            {modal === "inspection" && (
              <>
                <label>
                  Рекомендация
                  <textarea name="recommendation" />
                </label>
                <label>
                  Оценка состояния
                  <input
                    name="score"
                    type="number"
                    min="0"
                    max="1"
                    step="0.05"
                    defaultValue="0.8"
                  />
                </label>
                <label className="check">
                  <input name="defect" type="checkbox" /> Обнаружен дефект
                </label>
              </>
            )}
            {modal === "repair" && (
              <>
                <label>
                  Заменённые компоненты
                  <input name="recommendation" />
                </label>
                <label>
                  Длительность, минут
                  <input name="duration" type="number" defaultValue="60" />
                </label>
              </>
            )}
            {modal === "maintenance" && (
              <>
                <label>
                  Интервал, дней
                  <input name="duration" type="number" defaultValue="30" />
                </label>
                <label>
                  Следующая дата
                  <input name="date" type="datetime-local" required />
                </label>
              </>
            )}
            <button className="primary">Сохранить</button>
          </form>
        </Modal>
      )}
    </section>
  );
}
