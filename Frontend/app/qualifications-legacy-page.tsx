"use client";

/* eslint-disable react-hooks/set-state-in-effect */

import { FormEvent, useCallback, useEffect, useState } from "react";

import { api, config, Session } from "./api";

import { loadBrigades, type BrigadeRecord } from "./brigade-store";

import { type Notice, type Dict, text, Empty, Modal } from "./admin-shared";

import {
  type Skill,
  type CertType,
  type WorkProfile,
} from "./qualification-types";

/* eslint-disable @typescript-eslint/no-unused-vars */
function QualificationsPageLegacy({
  session,
  onNotice,
}: {
  session: Session;
  onNotice: Notice;
}) {
  const demo = session.accessToken === "demo",
    [tab, setTab] = useState<"skills" | "certs" | "brigades" | "people">(
      "skills",
    ),
    [skills, setSkills] = useState<Skill[]>([]),
    [certs, setCerts] = useState<CertType[]>([]),
    [people, setPeople] = useState<WorkProfile[]>([]),
    [selectedProfile, setSelectedProfile] = useState<WorkProfile>(),
    [grants, setGrants] = useState<Dict[]>([]),
    [certifications, setCertifications] = useState<Dict[]>([]),
    [modal, setModal] = useState(false),
    [editing, setEditing] = useState<Skill | CertType>(),
    [brigades] = useState<BrigadeRecord[]>(loadBrigades),
    [selectedBrigade, setSelectedBrigade] = useState<BrigadeRecord>(),
    [brigadeSkills, setBrigadeSkills] = useState<Dict[]>([]);
  const load = useCallback(async () => {
    if (demo) {
      setSkills([
        {
          id: "skill-demo-1",
          code: "ROAD_REPAIR",
          name: "Ремонт дорожного покрытия",
          description: "Локальное восстановление асфальта",
          active: true,
        },
        {
          id: "skill-demo-2",
          code: "ELECTRIC",
          name: "Электробезопасность",
          description: "Работы с сетями освещения",
          active: true,
        },
        {
          id: "skill-demo-3",
          code: "WATER",
          name: "Аварийный ремонт водопровода",
          description: "Локализация и устранение течей",
          active: true,
        },
      ]);
      setCerts([
        {
          id: "cert-demo-1",
          code: "ROAD_CERT",
          name: "Безопасность дорожных работ",
          description: "Работы в зоне движения",
          default_validity_days: 730,
          requires_file: true,
          active: true,
        },
        {
          id: "cert-demo-2",
          code: "ELECTRIC_CERT",
          name: "Допуск к электроустановкам",
          description: "Группа электробезопасности",
          default_validity_days: 365,
          requires_file: true,
          active: true,
        },
      ]);
      setPeople([
        {
          work_profile: {
            id: "work-demo-1",
            position: "Мастер дорожных работ",
            status: "ACTIVE",
          },
          user_profile: { full_name: "Алексей Смирнов" },
        },
        {
          work_profile: {
            id: "work-demo-2",
            position: "Аварийный техник",
            status: "ACTIVE",
          },
          user_profile: { full_name: "Ирина Волкова" },
        },
      ]);
      return;
    }
    try {
      const [s, c, p] = await Promise.all([
        api<{ skills: Skill[] }>(
          config.endpoints.skillsList,
          { limit: 100, offset: 0 },
          "POST",
          session.accessToken,
        ),
        api<{ certification_types: CertType[] }>(
          config.endpoints.certificationTypesList,
          { limit: 100, offset: 0 },
          "POST",
          session.accessToken,
        ),
        api<{ work_profiles: WorkProfile[] }>(
          config.endpoints.workProfilesList,
          { limit: 100, offset: 0 },
          "POST",
          session.accessToken,
        ),
      ]);
      setSkills(s.skills || []);
      setCerts(c.certification_types || []);
      setPeople(p.work_profiles || []);
    } catch (error) {
      onNotice(
        error instanceof Error
          ? error.message
          : "Не удалось загрузить квалификации",
      );
    }
  }, [demo, onNotice, session.accessToken]);
  useEffect(() => {
    void load();
  }, [load]);
  async function loadPerson(person: WorkProfile) {
    setSelectedProfile(person);
    if (demo) {
      setGrants([
        {
          id: "grant-demo-1",
          skill_id:
            person.work_profile.id === "work-demo-1"
              ? "skill-demo-1"
              : "skill-demo-3",
          proficiency_level: "Эксперт",
          active: true,
        },
      ]);
      setCertifications([
        {
          id: "worker-cert-demo",
          certification_type_id:
            person.work_profile.id === "work-demo-1"
              ? "cert-demo-1"
              : "cert-demo-2",
          status:
            person.work_profile.id === "work-demo-1" ? "VERIFIED" : "PENDING",
        },
      ]);
      return;
    }
    const [g, c] = await Promise.all([
      api<{ skill_grants: Dict[] }>(
        config.endpoints.workProfileSkillsList,
        { work_profile_id: person.work_profile.id },
        "POST",
        session.accessToken,
      ),
      api<{ certifications: Dict[] }>(
        config.endpoints.workProfileCertificationsList,
        { work_profile_id: person.work_profile.id, limit: 100, offset: 0 },
        "POST",
        session.accessToken,
      ),
    ]);
    setGrants(g.skill_grants || []);
    setCertifications(c.certifications || []);
  }
  async function loadBrigadeSkills(brigade: BrigadeRecord) {
    setSelectedBrigade(brigade);
    if (demo) {
      setBrigadeSkills([
        {
          id: `brigade-skill-${brigade.id}`,
          skill_id: brigade.id.includes("14") ? "skill-demo-1" : "skill-demo-3",
          skill: {
            id: brigade.id.includes("14") ? "skill-demo-1" : "skill-demo-3",
            name: brigade.id.includes("14")
              ? "Ремонт дорожного покрытия"
              : "Аварийный ремонт водопровода",
          },
        },
      ]);
      return;
    }
    const result = await api<{ skills: Dict[] }>(
      config.endpoints.brigadeSkillsList,
      { brigade_id: brigade.id, active: true },
      "POST",
      session.accessToken,
    );
    setBrigadeSkills(result.skills || []);
  }
  async function save(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const d = new FormData(e.currentTarget);
    if (tab === "skills") {
      const payload = {
        code: String(d.get("code")),
        name: String(d.get("name")),
        description: String(d.get("description")),
      };
      if (!demo)
        await api(
          editing
            ? config.endpoints.skillsUpdate
            : config.endpoints.skillsCreate,
          editing ? { id: editing.id, ...payload } : payload,
          "POST",
          session.accessToken,
        );
    } else if (tab === "certs") {
      const payload = {
        code: String(d.get("code")),
        name: String(d.get("name")),
        description: String(d.get("description")),
        default_validity_days: Number(d.get("days")),
        requires_file: d.get("file") !== null,
      };
      if (!demo)
        await api(
          editing
            ? config.endpoints.certificationTypesUpdate
            : config.endpoints.certificationTypesCreate,
          editing ? { id: editing.id, ...payload } : payload,
          "POST",
          session.accessToken,
        );
    } else if (tab === "brigades" && selectedBrigade) {
      if (!demo)
        await api(
          config.endpoints.brigadeSkillsAdd,
          {
            brigade_id: selectedBrigade.id,
            skill_id: String(d.get("skill_id")),
          },
          "POST",
          session.accessToken,
        );
      await loadBrigadeSkills(selectedBrigade);
    } else if (selectedProfile) {
      if (!demo)
        await api(
          config.endpoints.workProfileSkillsGrant,
          {
            work_profile_id: selectedProfile.work_profile.id,
            skill_id: String(d.get("skill_id")),
            proficiency_level: String(d.get("level")),
            reason: String(d.get("description")),
          },
          "POST",
          session.accessToken,
        );
      await loadPerson(selectedProfile);
    }
    setModal(false);
    setEditing(undefined);
    await load();
    onNotice("Квалификация сохранена");
  }
  async function deactivate() {
    if (!editing || tab !== "skills") return;
    if (!demo)
      await api(
        config.endpoints.skillsDeactivate,
        { id: editing.id },
        "POST",
        session.accessToken,
      );
    setModal(false);
    setEditing(undefined);
    await load();
    onNotice("Навык деактивирован");
  }
  async function removeBrigadeSkill(item: Dict) {
    if (!selectedBrigade) return;
    const skill = item.skill as Dict | undefined,
      skillId = text(skill?.id, item.skill_id);
    if (!demo)
      await api(
        config.endpoints.brigadeSkillsRemove,
        { brigade_id: selectedBrigade.id, skill_id: skillId },
        "POST",
        session.accessToken,
      );
    await loadBrigadeSkills(selectedBrigade);
    onNotice("Навык удалён у бригады");
  }
  async function removePersonGrant(item: Dict) {
    if (!selectedProfile) return;
    if (!demo) {
      await api(
        config.endpoints.workProfileSkillsRevoke,
        { id: text(item.id), reason: "Удалено администратором" },
        "POST",
        session.accessToken,
      );
      await loadPerson(selectedProfile);
    } else
      setGrants((current) => current.filter((grant) => grant.id !== item.id));
    onNotice("Навык удалён у сотрудника");
  }
  async function removePersonCertification(item: Dict) {
    if (!selectedProfile) return;
    if (!demo) {
      await api(
        config.endpoints.workProfileCertificationsRevoke,
        { id: text(item.id), reason: "Удалено администратором" },
        "POST",
        session.accessToken,
      );
      await loadPerson(selectedProfile);
    } else
      setCertifications((current) =>
        current.filter((cert) => cert.id !== item.id),
      );
    onNotice("Удостоверение удалено у сотрудника");
  }
  return (
    <section className="ops-page">
      <div className="ops-head">
        <div>
          <span className="eyebrow">Квалификации</span>
          <h2>Навыки и допуски сотрудников</h2>
          <p>
            Навыки служб, типы удостоверений и фактические допуски работников.
          </p>
        </div>
        <button
          className="primary"
          onClick={() => {
            setEditing(undefined);
            setModal(true);
          }}
        >
          +{" "}
          {tab === "skills"
            ? "Навык"
            : tab === "certs"
              ? "Тип допуска"
              : tab === "brigades"
                ? "Навык бригаде"
                : "Выдать навык"}
        </button>
      </div>
      <div className="ops-tabs">
        <button
          className={tab === "skills" ? "active" : ""}
          onClick={() => setTab("skills")}
        >
          Навыки <b>{skills.length}</b>
        </button>
        <button
          className={tab === "certs" ? "active" : ""}
          onClick={() => setTab("certs")}
        >
          Типы удостоверений <b>{certs.length}</b>
        </button>
        <button
          className={tab === "brigades" ? "active" : ""}
          onClick={() => setTab("brigades")}
        >
          Навыки бригад <b>{brigades.length}</b>
        </button>
        <button
          className={tab === "people" ? "active" : ""}
          onClick={() => setTab("people")}
        >
          Сотрудники <b>{people.length}</b>
        </button>
      </div>
      {["skills", "certs"].includes(tab) ? (
        <div className="catalog-list">
          {(tab === "skills" ? skills : certs).map((item) => (
            <button
              key={item.id}
              onClick={() => {
                setEditing(item);
                setModal(true);
              }}
            >
              <span
                className={`ops-state ${item.active ? "active" : "inactive"}`}
              >
                ● {item.active ? "ACTIVE" : "INACTIVE"}
              </span>
              <h3>{item.name}</h3>
              <p>{item.code}</p>
              <small>{item.description || "Без описания"}</small>
            </button>
          ))}
        </div>
      ) : tab === "brigades" ? (
        <div className={`ops-layout ${selectedBrigade ? "selected" : ""}`}>
          <div className="people-qualification-list">
            {brigades.map((brigade) => (
              <button
                key={brigade.id}
                onClick={() => void loadBrigadeSkills(brigade)}
              >
                <b>{brigade.name}</b>
                <span>{brigade.specialization}</span>
                <em>{brigade.status}</em>
              </button>
            ))}
          </div>
          {selectedBrigade && (
            <aside className="ops-detail">
              <button
                className="detail-close"
                onClick={() => setSelectedBrigade(undefined)}
              >
                ×
              </button>
              <span className="eyebrow">Навыки бригады</span>
              <h2>{selectedBrigade.name}</h2>
              {brigadeSkills.length ? (
                brigadeSkills.map((item, index) => (
                  <div
                    className="data-row action-row"
                    key={text(item.id, index)}
                  >
                    <span>
                      <b>{text((item.skill as Dict)?.name, item.skill_id)}</b>
                    </span>
                    <button
                      className="danger-action"
                      onClick={() => void removeBrigadeSkill(item)}
                    >
                      Удалить
                    </button>
                  </div>
                ))
              ) : (
                <Empty>Навыки не назначены</Empty>
              )}
            </aside>
          )}
        </div>
      ) : (
        <div className={`ops-layout ${selectedProfile ? "selected" : ""}`}>
          <div className="people-qualification-list">
            {people.map((person) => (
              <button
                key={person.work_profile.id}
                onClick={() => void loadPerson(person)}
                className={
                  selectedProfile?.work_profile.id === person.work_profile.id
                    ? "selected"
                    : ""
                }
              >
                <b>{person.user_profile.full_name}</b>
                <span>{person.work_profile.position}</span>
                <em>{person.work_profile.status}</em>
              </button>
            ))}
          </div>
          {selectedProfile && (
            <aside className="ops-detail">
              <button
                className="detail-close"
                onClick={() => setSelectedProfile(undefined)}
              >
                ×
              </button>
              <span className="eyebrow">Квалификация сотрудника</span>
              <h2>{selectedProfile.user_profile.full_name}</h2>
              <h3>Действующие навыки</h3>
              {grants.length ? (
                grants.map((grant, index) => (
                  <div className="data-row" key={text(grant.id, index)}>
                    <b>
                      {skills.find((s) => s.id === grant.skill_id)?.name ||
                        text(grant.skill_id)}
                    </b>
                    <span>
                      {text(grant.proficiency_level, "Уровень не задан")}
                    </span>
                  </div>
                ))
              ) : (
                <Empty>Навыки не назначены</Empty>
              )}
              <h3>Удостоверения</h3>
              {certifications.length ? (
                certifications.map((cert, index) => (
                  <div className="data-row" key={text(cert.id, index)}>
                    <b>
                      {certs.find((c) => c.id === cert.certification_type_id)
                        ?.name || text(cert.certification_type_id)}
                    </b>
                    <span>{text(cert.status)}</span>
                  </div>
                ))
              ) : (
                <Empty>Удостоверений нет</Empty>
              )}
            </aside>
          )}
        </div>
      )}
      {modal && (
        <Modal
          title={
            tab === "skills"
              ? editing
                ? "Изменить навык"
                : "Новый навык"
              : tab === "certs"
                ? editing
                  ? "Изменить тип удостоверения"
                  : "Новый тип удостоверения"
                : tab === "brigades"
                  ? "Назначить навык бригаде"
                  : "Выдать навык сотруднику"
          }
          onClose={() => {
            setModal(false);
            setEditing(undefined);
          }}
        >
          <form className="ops-form" onSubmit={save}>
            {["people", "brigades"].includes(tab) ? (
              <>
                <label>
                  Навык
                  <select name="skill_id">
                    {skills
                      .filter((s) => s.active)
                      .map((s) => (
                        <option key={s.id} value={s.id}>
                          {s.name}
                        </option>
                      ))}
                  </select>
                </label>
                {tab === "people" && (
                  <>
                    <label>
                      Уровень
                      <input name="level" placeholder="например, эксперт" />
                    </label>
                    <label>
                      Основание
                      <textarea name="description" required />
                    </label>
                  </>
                )}
              </>
            ) : (
              <>
                <label>
                  Код
                  <input name="code" defaultValue={editing?.code} required />
                </label>
                <label>
                  Название
                  <input name="name" defaultValue={editing?.name} required />
                </label>
                <label>
                  Описание
                  <textarea
                    name="description"
                    defaultValue={editing?.description}
                  />
                </label>
                {tab === "certs" && (
                  <>
                    <label>
                      Срок действия, дней
                      <input
                        name="days"
                        type="number"
                        defaultValue={
                          (editing as CertType)?.default_validity_days || 365
                        }
                      />
                    </label>
                    <label className="check">
                      <input
                        name="file"
                        type="checkbox"
                        defaultChecked={(editing as CertType)?.requires_file}
                      />{" "}
                      Требуется файл удостоверения
                    </label>
                  </>
                )}
              </>
            )}
            <div className="modal-buttons">
              {editing && tab === "skills" && (
                <button
                  type="button"
                  className="danger-action"
                  onClick={() => void deactivate()}
                >
                  Деактивировать
                </button>
              )}
              <button className="primary">Сохранить</button>
            </div>
          </form>
        </Modal>
      )}
    </section>
  );
}
