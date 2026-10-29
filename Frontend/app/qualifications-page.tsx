"use client";

/* eslint-disable react-hooks/set-state-in-effect */

import { FormEvent, useCallback, useEffect, useState } from "react";

import { api, config, Session } from "./api";

import { loadBrigades, type BrigadeRecord } from "./brigade-store";

import {
  qualificationLabel,
  qualificationStateClass,
} from "./qualification-labels";

import { type Notice, type Dict, text, Empty, Modal } from "./admin-shared";

import {
  type Skill,
  type CertType,
  type WorkProfile,
} from "./qualification-types";

export function QualificationsPage({
  session,
  onNotice,
}: {
  session: Session;
  onNotice: Notice;
}) {
  const demo = session.accessToken === "demo";
  const [tab, setTab] = useState<"skills" | "certs" | "brigades" | "people">(
    "skills",
  );
  const [skills, setSkills] = useState<Skill[]>([]);
  const [certs, setCerts] = useState<CertType[]>([]);
  const [people, setPeople] = useState<WorkProfile[]>([]);
  const [selectedProfile, setSelectedProfile] = useState<WorkProfile>();
  const [grants, setGrants] = useState<Dict[]>([]);
  const [certifications, setCertifications] = useState<Dict[]>([]);
  const [modal, setModal] = useState(false);
  const [editing, setEditing] = useState<Skill | CertType>();
  const [brigades, setBrigades] = useState<BrigadeRecord[]>(() =>
    demo ? loadBrigades() : [],
  );
  const [selectedBrigade, setSelectedBrigade] = useState<BrigadeRecord>();
  const [brigadeSkills, setBrigadeSkills] = useState<Dict[]>([]);

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
            status: "ON_SHIFT",
          },
          user_profile: { full_name: "Ирина Волкова" },
        },
      ]);
      return;
    }
    try {
      const [skillResult, certResult, profileResult, brigadeResult] =
        await Promise.all([
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
          api<{ brigades: BrigadeRecord[] }>(
            config.endpoints.brigadesList,
            { limit: 100, offset: 0 },
            "POST",
            session.accessToken,
          ),
        ]);
      setSkills(skillResult.skills || []);
      setCerts(certResult.certification_types || []);
      setPeople(profileResult.work_profiles || []);
      setBrigades(brigadeResult.brigades || []);
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
      const road = person.work_profile.id === "work-demo-1";
      setGrants([
        {
          id: `grant-${person.work_profile.id}`,
          skill_id: road ? "skill-demo-1" : "skill-demo-3",
          proficiency_level: road ? "Эксперт" : "Специалист",
          source_type: "MANUAL",
          active: true,
        },
      ]);
      setCertifications([
        {
          id: `certificate-${person.work_profile.id}`,
          certification_type_id: road ? "cert-demo-1" : "cert-demo-2",
          status: road ? "VERIFIED" : "PENDING",
        },
      ]);
      return;
    }
    const [grantResult, certResult] = await Promise.all([
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
    setGrants(grantResult.skill_grants || []);
    setCertifications(certResult.certifications || []);
  }

  async function loadBrigadeSkills(brigade: BrigadeRecord) {
    setSelectedBrigade(brigade);
    if (demo) {
      const road = brigade.id.includes("14");
      setBrigadeSkills([
        {
          id: `brigade-skill-${brigade.id}`,
          skill_id: road ? "skill-demo-1" : "skill-demo-3",
          skill: {
            id: road ? "skill-demo-1" : "skill-demo-3",
            name: road
              ? "Ремонт дорожного покрытия"
              : "Аварийный ремонт водопровода",
          },
        },
      ]);
      return;
    }
    try {
      const result = await api<{ skills: Dict[] }>(
        config.endpoints.brigadeSkillsList,
        { brigade_id: brigade.id, active: true },
        "POST",
        session.accessToken,
      );
      setBrigadeSkills(result.skills || []);
    } catch (error) {
      setSelectedBrigade(undefined);
      setBrigadeSkills([]);
      onNotice(
        error instanceof Error
          ? error.message
          : "Не удалось загрузить навыки бригады",
      );
    }
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    if (tab === "skills") {
      const payload = {
        code: String(data.get("code")),
        name: String(data.get("name")),
        description: String(data.get("description")),
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
        code: String(data.get("code")),
        name: String(data.get("name")),
        description: String(data.get("description")),
        default_validity_days: Number(data.get("days")),
        requires_file: data.get("file") !== null,
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
      const skillId = String(data.get("skill_id"));
      if (demo) {
        const skill = skills.find((item) => item.id === skillId);
        setBrigadeSkills((current) => [
          ...current,
          { id: `brigade-skill-${Date.now()}`, skill_id: skillId, skill },
        ]);
      } else {
        await api(
          config.endpoints.brigadeSkillsAdd,
          { brigade_id: selectedBrigade.id, skill_id: skillId },
          "POST",
          session.accessToken,
        );
        await loadBrigadeSkills(selectedBrigade);
      }
    } else if (selectedProfile) {
      const skillId = String(data.get("skill_id"));
      if (demo) {
        setGrants((current) => [
          ...current,
          {
            id: `grant-demo-${Date.now()}`,
            skill_id: skillId,
            proficiency_level: String(data.get("level")) || "Уровень не задан",
            source_type: "MANUAL",
            active: true,
          },
        ]);
      } else {
        await api(
          config.endpoints.workProfileSkillsGrant,
          {
            work_profile_id: selectedProfile.work_profile.id,
            skill_id: skillId,
            proficiency_level: String(data.get("level")),
            reason: String(data.get("description")),
          },
          "POST",
          session.accessToken,
        );
        await loadPerson(selectedProfile);
      }
    }
    setModal(false);
    setEditing(undefined);
    if (tab === "skills" || tab === "certs") await load();
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
    if (demo)
      setBrigadeSkills((current) =>
        current.filter((value) => value.id !== item.id),
      );
    else {
      await api(
        config.endpoints.brigadeSkillsRemove,
        { brigade_id: selectedBrigade.id, skill_id: skillId },
        "POST",
        session.accessToken,
      );
      await loadBrigadeSkills(selectedBrigade);
    }
    onNotice("Навык удалён у бригады");
  }
  async function removePersonGrant(item: Dict) {
    if (!selectedProfile) return;
    if (demo)
      setGrants((current) => current.filter((value) => value.id !== item.id));
    else {
      await api(
        config.endpoints.workProfileSkillsRevoke,
        { id: text(item.id), reason: "Удалено администратором" },
        "POST",
        session.accessToken,
      );
      await loadPerson(selectedProfile);
    }
    onNotice("Навык удалён у сотрудника");
  }
  async function removePersonCertification(item: Dict) {
    if (!selectedProfile) return;
    if (demo)
      setCertifications((current) =>
        current.filter((value) => value.id !== item.id),
      );
    else {
      await api(
        config.endpoints.workProfileCertificationsRevoke,
        { id: text(item.id), reason: "Удалено администратором" },
        "POST",
        session.accessToken,
      );
      await loadPerson(selectedProfile);
    }
    onNotice("Удостоверение удалено у сотрудника");
  }

  const openCreate = () => {
    setEditing(undefined);
    setModal(true);
  };
  const changeTab = (value: typeof tab) => {
    setTab(value);
    setSelectedProfile(undefined);
    setSelectedBrigade(undefined);
  };
  return (
    <section className="ops-page qualification-page">
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
          disabled={
            (tab === "people" && !selectedProfile) ||
            (tab === "brigades" && !selectedBrigade)
          }
          onClick={openCreate}
        >
          +{" "}
          {tab === "skills"
            ? "Навык"
            : tab === "certs"
              ? "Тип удостоверения"
              : tab === "brigades"
                ? "Навык бригаде"
                : "Навык сотруднику"}
        </button>
      </div>
      <div className="ops-tabs">
        <button
          className={tab === "skills" ? "active" : ""}
          onClick={() => changeTab("skills")}
        >
          Навыки <b>{skills.length}</b>
        </button>
        <button
          className={tab === "certs" ? "active" : ""}
          onClick={() => changeTab("certs")}
        >
          Типы удостоверений <b>{certs.length}</b>
        </button>
        <button
          className={tab === "brigades" ? "active" : ""}
          onClick={() => changeTab("brigades")}
        >
          Навыки бригад <b>{brigades.length}</b>
        </button>
        <button
          className={tab === "people" ? "active" : ""}
          onClick={() => changeTab("people")}
        >
          Сотрудники <b>{people.length}</b>
        </button>
      </div>
      {(tab === "skills" || tab === "certs") && (
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
                className={`ops-state ${qualificationStateClass(item.active ? "ACTIVE" : "INACTIVE")}`}
              >
                ● {qualificationLabel(item.active ? "ACTIVE" : "INACTIVE")}
              </span>
              <h3>{item.name}</h3>
              <p>{item.code}</p>
              <small>{item.description || "Без описания"}</small>
            </button>
          ))}
        </div>
      )}
      {tab === "brigades" && (
        <div className={`ops-layout ${selectedBrigade ? "selected" : ""}`}>
          <div className="people-qualification-list">
            {brigades.map((brigade) => (
              <button
                key={brigade.id}
                className={selectedBrigade?.id === brigade.id ? "selected" : ""}
                onClick={() => void loadBrigadeSkills(brigade)}
              >
                <b>{brigade.name}</b>
                <span>{brigade.specialization}</span>
                <em
                  className={`ops-state ${qualificationStateClass(brigade.status)}`}
                >
                  {qualificationLabel(brigade.status)}
                </em>
              </button>
            ))}
          </div>
          {selectedBrigade && (
            <aside className="ops-detail qualification-person-detail">
              <button
                className="detail-close"
                onClick={() => setSelectedBrigade(undefined)}
              >
                ×
              </button>
              <span className="eyebrow">Навыки бригады</span>
              <h2>{selectedBrigade.name}</h2>
              <div className="qualification-subhead">
                <h3>Назначенные навыки</h3>
                <button className="ghost small" onClick={openCreate}>
                  + Добавить
                </button>
              </div>
              {brigadeSkills.length ? (
                brigadeSkills.map((item, index) => (
                  <div
                    className="data-row action-row"
                    key={text(item.id, index)}
                  >
                    <span>
                      <b>
                        {text(
                          (item.skill as Dict)?.name ??
                            skills.find((skill) => skill.id === item.skill_id)
                              ?.name,
                          item.skill_id,
                        )}
                      </b>
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
      )}
      {tab === "people" && (
        <div className={`ops-layout ${selectedProfile ? "selected" : ""}`}>
          <div className="people-qualification-list">
            {people.map((person) => (
              <button
                key={person.work_profile.id}
                className={
                  selectedProfile?.work_profile.id === person.work_profile.id
                    ? "selected"
                    : ""
                }
                onClick={() => void loadPerson(person)}
              >
                <b>{person.user_profile.full_name}</b>
                <span>{person.work_profile.position}</span>
                <em
                  className={`ops-state ${qualificationStateClass(person.work_profile.status)}`}
                >
                  {qualificationLabel(person.work_profile.status)}
                </em>
              </button>
            ))}
          </div>
          {selectedProfile && (
            <aside className="ops-detail qualification-person-detail">
              <button
                className="detail-close"
                onClick={() => setSelectedProfile(undefined)}
              >
                ×
              </button>
              <span className="eyebrow">Квалификация сотрудника</span>
              <h2>{selectedProfile.user_profile.full_name}</h2>
              <div className="qualification-subhead">
                <h3>Действующие навыки</h3>
                <button className="ghost small" onClick={openCreate}>
                  + Добавить
                </button>
              </div>
              {grants.filter((item) => item.active !== false).length ? (
                grants
                  .filter((item) => item.active !== false)
                  .map((grant, index) => (
                    <div
                      className="data-row action-row"
                      key={text(grant.id, index)}
                    >
                      <span>
                        <b>
                          {skills.find((skill) => skill.id === grant.skill_id)
                            ?.name || text(grant.skill_id)}
                        </b>
                        <small>
                          {text(grant.proficiency_level, "Уровень не задан")} ·{" "}
                          {qualificationLabel(grant.source_type)}
                        </small>
                      </span>
                      <button
                        className="danger-action"
                        onClick={() => void removePersonGrant(grant)}
                      >
                        Удалить
                      </button>
                    </div>
                  ))
              ) : (
                <Empty>Навыки не назначены</Empty>
              )}
              <div className="qualification-subhead">
                <h3>Удостоверения</h3>
              </div>
              {certifications.length ? (
                certifications.map((cert, index) => (
                  <div
                    className="data-row action-row"
                    key={text(cert.id, index)}
                  >
                    <span>
                      <b>
                        {certs.find(
                          (item) => item.id === cert.certification_type_id,
                        )?.name || text(cert.certification_type_id)}
                      </b>
                      <small
                        className={`ops-state ${qualificationStateClass(cert.status)}`}
                      >
                        {qualificationLabel(cert.status)}
                      </small>
                    </span>
                    {["PENDING", "VERIFIED"].includes(String(cert.status)) && (
                      <button
                        className="danger-action"
                        onClick={() => void removePersonCertification(cert)}
                      >
                        Удалить
                      </button>
                    )}
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
            {tab === "people" || tab === "brigades" ? (
              <>
                <label>
                  Навык
                  <select name="skill_id" required>
                    {skills
                      .filter((item) => item.active)
                      .map((item) => (
                        <option key={item.id} value={item.id}>
                          {item.name}
                        </option>
                      ))}
                  </select>
                </label>
                {tab === "people" && (
                  <>
                    <label>
                      Уровень
                      <input
                        name="level"
                        placeholder="Например: эксперт"
                        required
                      />
                    </label>
                    <label>
                      Основание
                      <textarea name="description" rows={3} required />
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
                        min="1"
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
