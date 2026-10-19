import { expect, test, type APIRequestContext } from "@playwright/test";
import { apiLogin, bearer } from "./support/auth";
import { gatewayUrl } from "./support/environment";

async function post(request: APIRequestContext, path: string, token: string, data: unknown = {}) {
  const response = await request.post(`${gatewayUrl}${path}`, { headers: bearer(token), data });
  const body = await response.json().catch(() => ({}));
  expect(response.status(), `${path}: ${response.status()} ${JSON.stringify(body)}`).toBeLessThan(500);
  return { response, body };
}

test.describe("Контракты API, используемые фронтендом", () => {
  test("health и профиль авторизованного пользователя", async ({ request }) => {
    const health = await request.get(`${gatewayUrl}/health`);
    await expect(health).toBeOK();
    expect(await health.json()).toMatchObject({ status: "ok" });
    const token = await apiLogin(request, "admin");
    const me = await request.get(`${gatewayUrl}/auth/me`, { headers: bearer(token) });
    await expect(me).toBeOK();
    expect(await me.json()).toMatchObject({ email: "demo.admin@city.local" });
  });

  test("административные списки отвечают и сохраняют ожидаемую форму", async ({ request }) => {
    const token = await apiLogin(request, "admin");
    const cases: Array<[string, unknown, string[]]> = [
      ["/tickets/list", { limit: 100, offset: 0 }, ["tickets"]],
      ["/departments/list", { limit: 100, offset: 0 }, ["departments"]],
      ["/brigades/list", { limit: 100, offset: 0 }, ["brigades"]],
      ["/work-profiles/list", { limit: 100, offset: 0 }, ["work_profiles", "profiles"]],
      ["/ticket-categories/list", { limit: 100, offset: 0 }, ["categories"]],
      ["/skills/list", { limit: 100, offset: 0 }, ["skills"]],
      ["/certification-types/list", { limit: 100, offset: 0 }, ["certification_types", "types"]],
      ["/sla/rules/list", { limit: 100, offset: 0 }, ["rules"]],
      ["/sla/tickets/list", { limit: 100, offset: 0 }, ["slas"]],
      ["/assets/list", { limit: 100, offset: 0 }, ["assets"]],
      ["/reports/list", { limit: 100, offset: 0 }, ["reports"]],
      ["/audit/list", { limit: 100, offset: 0 }, ["entries", "events"]],
      ["/dispatch/list", { limit: 100, offset: 0 }, ["operations", "items"]],
      ["/routing/list", { limit: 100, offset: 0 }, ["routes"]],
      ["/locations/current-batch", { brigade_ids: ["30000000-0000-4000-8000-000000000001"] }, ["positions", "locations"]],
    ];
    for (const [path, data, possibleKeys] of cases) {
      const { response, body } = await post(request, path, token, data);
      expect(response.ok(), `${path}: ${JSON.stringify(body)}`).toBeTruthy();
      expect(possibleKeys.some((key) => Object.hasOwn(body, key)), `${path}: missing ${possibleKeys.join("/")}`).toBeTruthy();
    }
  });

  test("составной междепартаментный инцидент проходит полный жизненный цикл", async ({ request }) => {
    const adminToken = await apiLogin(request, "admin");
    const dispatcherToken = await apiLogin(request, "dispatcher");
    const dispatcherMe = await request.get(`${gatewayUrl}/auth/me`, { headers: bearer(dispatcherToken) });
    await expect(dispatcherMe).toBeOK();
    const dispatcherUser = await dispatcherMe.json() as { user_id: string };
    const workingDepartment = await post(
      request,
      "/profile-checks/resolve-working-department",
      dispatcherToken,
      { user_id: dispatcherUser.user_id },
    );
    expect(workingDepartment.response.ok(), JSON.stringify(workingDepartment.body)).toBeTruthy();
    expect(workingDepartment.body).toEqual(expect.objectContaining({
      can_operate: true,
      department_id: expect.any(String),
    }));

    const dispatcherDepartmentID = workingDepartment.body.department_id as string;
    const departments = await post(request, "/departments/list", adminToken, { limit: 100, offset: 0 });
    const foreignDepartment = (departments.body.departments as Array<{ id: string }>).find(
      department => department.id !== dispatcherDepartmentID,
    );
    expect(foreignDepartment, "нужен второй департамент для междепартаментного теста").toBeTruthy();

    const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const category = await post(request, "/ticket-categories/create", adminToken, {
      code: `e2e_multi_${suffix}`,
      name: `E2E междепартаментная категория ${suffix}`,
      description: "Изолированная категория для проверки жизненного цикла составного инцидента",
    });
    expect(category.response.status(), JSON.stringify(category.body)).toBe(201);
    const categoryID = category.body.category.id as string;

    const first = await post(request, "/tickets/requests/create", adminToken, {
      department_id: foreignDepartment!.id,
      category_id: categoryID,
      title: `E2E составной инцидент A ${suffix}`,
      description: "Работа первого департамента",
      priority: "HIGH",
      address: "Москва, Тверская улица, 1",
      latitude: 55.757393,
      longitude: 37.613218,
    });
    expect(first.response.status(), JSON.stringify(first.body)).toBe(201);

    const second = await post(request, "/tickets/requests/create", dispatcherToken, {
      department_id: dispatcherDepartmentID,
      category_id: categoryID,
      title: `E2E составной инцидент B ${suffix}`,
      description: "Работа департамента диспетчера",
      priority: "HIGH",
      address: "Москва, Петровка, 2",
      latitude: 55.761393,
      longitude: 37.617218,
    });
    expect(second.response.status(), JSON.stringify(second.body)).toBe(201);

    const incidentID = first.body.incident.id as string;
    const firstRequestID = first.body.request.id as string;
    const secondRequestID = second.body.request.id as string;
    const attach = await post(request, "/tickets/requests/attach", dispatcherToken, {
      incident_id: incidentID,
      request_id: secondRequestID,
      reason: "Обе работы устраняют один городской инцидент",
    });
    expect(attach.response.ok(), JSON.stringify(attach.body)).toBeTruthy();
    expect(attach.body.request).toEqual(expect.objectContaining({
      id: secondRequestID,
      incident_id: incidentID,
      department_id: dispatcherDepartmentID,
      ticket_type: "REQUEST",
    }));

    const composition = await post(request, "/tickets/requests/list", dispatcherToken, {
      incident_id: incidentID,
      limit: 1,
      offset: 0,
    });
    expect(composition.response.ok(), JSON.stringify(composition.body)).toBeTruthy();
    expect(composition.body).toEqual(expect.objectContaining({
      total: 2,
      completed: 0,
      department_count: 2,
      is_composite: true,
      all_parts_completed: false,
    }));
    expect(composition.body.requests).toHaveLength(1);

    const detach = await post(request, "/tickets/requests/detach", dispatcherToken, {
      request_id: secondRequestID,
      reason: "Проверка исключения части из инцидента",
    });
    expect(detach.response.ok(), JSON.stringify(detach.body)).toBeTruthy();
    expect(detach.body.request.incident_id || "").toBe("");

    const compositionAfterDetach = await post(request, "/tickets/requests/list", adminToken, {
      incident_id: incidentID,
      limit: 100,
      offset: 0,
    });
    expect(compositionAfterDetach.body).toEqual(expect.objectContaining({
      total: 1,
      department_count: 1,
      is_composite: false,
    }));

    const reattach = await post(request, "/tickets/requests/attach", dispatcherToken, {
      incident_id: incidentID,
      request_id: secondRequestID,
      reason: "Возвращаем часть для проверки автоматического закрытия",
    });
    expect(reattach.response.ok(), JSON.stringify(reattach.body)).toBeTruthy();

    const transition = async (ticketID: string, newStatus: "assigned" | "in_progress") => {
      const result = await post(request, "/tickets/change-status", adminToken, {
        ticket_id: ticketID,
        new_status: newStatus,
        comment: `E2E transition to ${newStatus}`,
      });
      expect(result.response.ok(), `${ticketID} -> ${newStatus}: ${JSON.stringify(result.body)}`).toBeTruthy();
    };
    await transition(incidentID, "assigned");
    await transition(incidentID, "in_progress");

    const prematureCompletion = await request.post(`${gatewayUrl}/tickets/complete`, {
      headers: bearer(adminToken),
      data: { ticket_id: incidentID, comment: "Инцидент ещё не должен закрываться" },
    });
    expect(prematureCompletion.status()).toBe(409);

    for (const requestID of [firstRequestID, secondRequestID]) {
      await transition(requestID, "assigned");
      await transition(requestID, "in_progress");
    }

    const firstCompletion = await post(request, "/tickets/complete", adminToken, {
      ticket_id: firstRequestID,
      comment: "Первый департамент завершил работу",
    });
    expect(firstCompletion.response.ok(), JSON.stringify(firstCompletion.body)).toBeTruthy();

    const activeIncident = await post(request, "/tickets/get", adminToken, { ticket_id: incidentID });
    expect(activeIncident.body.ticket.status).toBe("IN_PROGRESS");

    const secondCompletion = await post(request, "/tickets/complete", adminToken, {
      ticket_id: secondRequestID,
      comment: "Второй департамент завершил работу",
    });
    expect(secondCompletion.response.ok(), JSON.stringify(secondCompletion.body)).toBeTruthy();

    const completedIncident = await post(request, "/tickets/get", adminToken, { ticket_id: incidentID });
    expect(completedIncident.body.ticket.status).toBe("DONE");
    const completedComposition = await post(request, "/tickets/requests/list", dispatcherToken, {
      incident_id: incidentID,
      limit: 100,
      offset: 0,
    });
    expect(completedComposition.body).toEqual(expect.objectContaining({
      total: 2,
      completed: 2,
      department_count: 2,
      is_composite: true,
      all_parts_completed: true,
    }));
  });

  test("аналитика возвращает все блоки для расширенного экрана", async ({ request }) => {
    const token = await apiLogin(request, "admin");
    const filter = {};
    for (const [path, data] of [
      ["/analytics/tickets/overview", { filter }],
      ["/analytics/sla/summary", { filter }],
      ["/analytics/tickets/daily", { filter }],
      ["/analytics/tickets/breakdown", { filter, dimension: "status", limit: 100 }],
      ["/analytics/assets/summary", { filter }],
      ["/analytics/dispatch/failures", { filter }],
      ["/analytics/brigades/workload", { filter }],
      ["/analytics/workers/active", { filter }],
      ["/analytics/dispatch/funnel", { filter }],
      ["/analytics/dispatch/effectiveness", { filter }],
      ["/analytics/operations/insights", { filter }],
      ["/analytics/projections/health", {}],
      ["/analytics/dispatch/operations", { filter }],
      ["/analytics/brigades/performance", { filter }],
    ] as const) {
      const { response } = await post(request, path, token, data);
      expect(response.ok(), path).toBeTruthy();
    }

    const health = await post(request, "/analytics/projections/health", token);
    expect(health.body).toEqual(expect.objectContaining({ total_events: expect.anything() }));
    for (const field of ["projected_events", "missing_projection_events", "projection_error_rate", "freshness_seconds"]) {
      if (Object.hasOwn(health.body, field)) expect(typeof health.body[field]).toBe("number");
    }
    const workers = await post(request, "/analytics/workers/active", token, { filter });
    if (Object.hasOwn(workers.body, "on_shift")) expect(typeof workers.body.on_shift).toBe("number");
    const performance = await post(request, "/analytics/brigades/performance", token, { filter });
    for (const field of ["shift_count", "shift_hours", "busy_hours", "average_parallel_tasks", "completed_per_shift", "utilization_rate"]) {
      if (Object.hasOwn(performance.body, field)) expect(typeof performance.body[field]).toBe("number");
    }
  });

  test("RBAC блокирует административный аудит для жителя", async ({ request }) => {
    const token = await apiLogin(request, "user");
    const response = await request.post(`${gatewayUrl}/audit/list`, {
      headers: bearer(token), data: { limit: 10, offset: 0 },
    });
    expect([401, 403]).toContain(response.status());
    const body = await response.json();
    expect(body).toMatchObject({ code: expect.stringMatching(/UNAUTHENTICATED|PERMISSION_DENIED/) });
  });
});
