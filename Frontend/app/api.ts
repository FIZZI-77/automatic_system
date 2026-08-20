export type Role = "user" | "worker" | "dispatcher" | "admin";

export type Session = {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  user?: CurrentUser;
};

export type CurrentUser = {
  user_id: string;
  email: string;
  roles: string[];
  permissions: string[];
  is_active: boolean;
  email_verified: boolean;
  department_id?: string;
};

export type Ticket = {
  id: string;
  department_id: string;
  category_id: string;
  user_id: string;
  brigade_id?: string;
  title: string;
  description: string;
  status: string;
  priority: string;
  address: string;
  latitude: number;
  longitude: number;
  created_at: number;
  updated_at: number;
  assigned_at?: number;
  completed_at?: number;
  canceled_at?: number;
  created_by_name?: string;
  accepted_by_name?: string;
};

export type Position = {
  vehicle_id: string;
  brigade_id: string;
  latitude: number;
  longitude: number;
  speed_kmh: number;
  heading: number;
  recorded_at: number;
  department_id?: string;
};

export const config = {
  apiBase: process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8081",
  wsUrl: process.env.NEXT_PUBLIC_NOTIFICATIONS_WS_URL || "ws://localhost:8081/notifications/ws",
  yandexMapsApiUrl: process.env.NEXT_PUBLIC_YANDEX_MAPS_API_URL || "https://api-maps.yandex.ru/v3/",
  yandexMapsApiKey: process.env.NEXT_PUBLIC_YANDEX_MAPS_API_KEY || "",
  yandexMapsLang: process.env.NEXT_PUBLIC_YANDEX_MAPS_LANG || "ru_RU",
  yandexMapsEmbedUrl: process.env.NEXT_PUBLIC_YANDEX_MAPS_EMBED_URL || "https://yandex.ru/map-widget/v1/?ll=37.618423%2C55.751244&z=12",
  openMapTileUrl: process.env.NEXT_PUBLIC_OPEN_MAP_TILE_URL || "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
  hotMapTileUrl: process.env.NEXT_PUBLIC_HOT_MAP_TILE_URL || "https://{s}.tile.openstreetmap.fr/hot/{z}/{x}/{y}.png",
  topographicMapTileUrl: process.env.NEXT_PUBLIC_TOPO_MAP_TILE_URL || "https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png",
  openMapAttribution: process.env.NEXT_PUBLIC_OPEN_MAP_ATTRIBUTION || "© OpenStreetMap contributors",
  endpoints: {
    login: process.env.NEXT_PUBLIC_API_AUTH_LOGIN || "/auth/login",
    register: process.env.NEXT_PUBLIC_API_AUTH_REGISTER || "/auth/register",
    refresh: process.env.NEXT_PUBLIC_API_AUTH_REFRESH || "/auth/refresh",
    logout: process.env.NEXT_PUBLIC_API_AUTH_LOGOUT || "/auth/logout",
    logoutAll: process.env.NEXT_PUBLIC_API_AUTH_LOGOUT_ALL || "/auth/logout-all",
    verifyEmail: process.env.NEXT_PUBLIC_API_AUTH_VERIFY_EMAIL || "/auth/verify-email",
    sendVerificationEmail: process.env.NEXT_PUBLIC_API_AUTH_SEND_VERIFICATION || "/auth/send-verification-email",
    requestPasswordReset: process.env.NEXT_PUBLIC_API_AUTH_REQUEST_PASSWORD_RESET || "/auth/request-password-reset",
    resetPassword: process.env.NEXT_PUBLIC_API_AUTH_RESET_PASSWORD || "/auth/reset-password",
    changePassword: process.env.NEXT_PUBLIC_API_AUTH_CHANGE_PASSWORD || "/auth/change-password",
    me: process.env.NEXT_PUBLIC_API_AUTH_ME || "/auth/me",
    profile: process.env.NEXT_PUBLIC_API_PROFILE_ME || "/user-profiles/me",
    ticketsList: process.env.NEXT_PUBLIC_API_TICKETS_LIST || "/tickets/list",
    ticketsGet: process.env.NEXT_PUBLIC_API_TICKETS_GET || "/tickets/get",
    ticketsUpdate: process.env.NEXT_PUBLIC_API_TICKETS_UPDATE || "/tickets/update",
    ticketsCancel: process.env.NEXT_PUBLIC_API_TICKETS_CANCEL || "/tickets/cancel",
    ticketsHistory: process.env.NEXT_PUBLIC_API_TICKETS_HISTORY || "/tickets/status-history",
    ticketsCreate: process.env.NEXT_PUBLIC_API_TICKETS_CREATE || "/tickets/create",
    ticketsStatus: process.env.NEXT_PUBLIC_API_TICKETS_STATUS || "/tickets/change-status",
    ticketsAssign: process.env.NEXT_PUBLIC_API_TICKETS_ASSIGN || "/tickets/assign-brigade",
    ticketsComplete: process.env.NEXT_PUBLIC_API_TICKETS_COMPLETE || "/tickets/complete",
    ticketReportsCreate: process.env.NEXT_PUBLIC_API_TICKET_REPORTS_CREATE || "/tickets/reports/create",
    ticketReportsList: process.env.NEXT_PUBLIC_API_TICKET_REPORTS_LIST || "/tickets/reports/list",
    completionReportsCreate: process.env.NEXT_PUBLIC_API_COMPLETION_REPORTS_CREATE || "/reports/completion/create",
    filesUploadCreate: process.env.NEXT_PUBLIC_API_FILES_UPLOAD_CREATE || "/files/uploads/create",
    filesUploadConfirm: process.env.NEXT_PUBLIC_API_FILES_UPLOAD_CONFIRM || "/files/uploads/confirm",
    filesList: process.env.NEXT_PUBLIC_API_FILES_LIST || "/files/list",
    filesDownload: process.env.NEXT_PUBLIC_API_FILES_DOWNLOAD || "/files/download-url",
    filesDelete: process.env.NEXT_PUBLIC_API_FILES_DELETE || "/files/delete",
    brigadesList: process.env.NEXT_PUBLIC_API_BRIGADES_LIST || "/brigades/list",
    brigadesCreate: process.env.NEXT_PUBLIC_API_BRIGADES_CREATE || "/brigades/create",
    brigadesUpdate: process.env.NEXT_PUBLIC_API_BRIGADES_UPDATE || "/brigades/update",
    brigadesStatus: process.env.NEXT_PUBLIC_API_BRIGADES_STATUS || "/brigades/set-status",
    brigadesGet: process.env.NEXT_PUBLIC_API_BRIGADES_GET || "/brigades/get",
    brigadesDeactivate: process.env.NEXT_PUBLIC_API_BRIGADES_DEACTIVATE || "/brigades/deactivate",
    brigadesArchive: process.env.NEXT_PUBLIC_API_BRIGADES_ARCHIVE || "/brigades/archive",
    brigadesHistory: process.env.NEXT_PUBLIC_API_BRIGADES_HISTORY || "/brigades/status-history",
    brigadesAvailable: process.env.NEXT_PUBLIC_API_BRIGADES_AVAILABLE || "/brigades/available",
    brigadesCanHandle: process.env.NEXT_PUBLIC_API_BRIGADES_CAN_HANDLE || "/brigades/can-handle-ticket",
    brigadeByUser: process.env.NEXT_PUBLIC_API_BRIGADE_BY_USER || "/brigades/get-by-user",
    brigadeZonesCreate: process.env.NEXT_PUBLIC_API_BRIGADE_ZONES_CREATE || "/brigade-zones/create",
    brigadeZonesList: process.env.NEXT_PUBLIC_API_BRIGADE_ZONES_LIST || "/brigade-zones/list",
    brigadeZonesUpdate: process.env.NEXT_PUBLIC_API_BRIGADE_ZONES_UPDATE || "/brigade-zones/update",
    brigadeZonesDelete: process.env.NEXT_PUBLIC_API_BRIGADE_ZONES_DELETE || "/brigade-zones/delete",
    brigadeZonesCovers: process.env.NEXT_PUBLIC_API_BRIGADE_ZONES_COVERS || "/brigade-zones/covers-point",
    brigadeZonesFind: process.env.NEXT_PUBLIC_API_BRIGADE_ZONES_FIND || "/brigade-zones/find-by-point",
    brigadeMembersAdd: process.env.NEXT_PUBLIC_API_BRIGADE_MEMBERS_ADD || "/brigade-members/add",
    brigadeMembersRemove: process.env.NEXT_PUBLIC_API_BRIGADE_MEMBERS_REMOVE || "/brigade-members/remove",
    brigadeMembersRole: process.env.NEXT_PUBLIC_API_BRIGADE_MEMBERS_ROLE || "/brigade-members/change-role",
    brigadeMembersAvailability: process.env.NEXT_PUBLIC_API_BRIGADE_MEMBERS_AVAILABILITY || "/brigade-members/set-availability",
    brigadeMembersHistory: process.env.NEXT_PUBLIC_API_BRIGADE_MEMBERS_HISTORY || "/brigade-members/history",
    brigadeMembersStatusHistory: process.env.NEXT_PUBLIC_API_BRIGADE_MEMBERS_STATUS_HISTORY || "/brigade-members/status-history",
    departmentsCreate: process.env.NEXT_PUBLIC_API_DEPARTMENTS_CREATE || "/departments/create",
    departmentsList: process.env.NEXT_PUBLIC_API_DEPARTMENTS_LIST || "/departments/list",
    departmentsUpdate: process.env.NEXT_PUBLIC_API_DEPARTMENTS_UPDATE || "/departments/update",
    departmentsGet: process.env.NEXT_PUBLIC_API_DEPARTMENTS_GET || "/departments/get",
    departmentsDelete: process.env.NEXT_PUBLIC_API_DEPARTMENTS_DELETE || "/departments/delete",
    userProfilesCreate: process.env.NEXT_PUBLIC_API_USER_PROFILES_CREATE || "/user-profiles/create",
    workProfilesCreate: process.env.NEXT_PUBLIC_API_WORK_PROFILES_CREATE || "/work-profiles/create",
    locationsBatch: process.env.NEXT_PUBLIC_API_LOCATIONS_BATCH || "/locations/current-batch",
    locationsRecord: process.env.NEXT_PUBLIC_API_LOCATIONS_RECORD || "/locations/record",
    locationsCurrent: process.env.NEXT_PUBLIC_API_LOCATIONS_CURRENT || "/locations/current",
    locationsHistory: process.env.NEXT_PUBLIC_API_LOCATIONS_HISTORY || "/locations/history",
    locationsNearby: process.env.NEXT_PUBLIC_API_LOCATIONS_NEARBY || "/locations/nearby",
    routesBuild: process.env.NEXT_PUBLIC_API_ROUTES_BUILD || "/routing/build",
    routesMatrix: process.env.NEXT_PUBLIC_API_ROUTES_MATRIX || "/routing/matrix",
    routesRankCandidates: process.env.NEXT_PUBLIC_API_ROUTES_RANK || "/routing/rank-candidates",
    routesCreate: process.env.NEXT_PUBLIC_API_ROUTES_CREATE || "/routing/create",
    routesGet: process.env.NEXT_PUBLIC_API_ROUTES_GET || "/routing/get",
    routesRecalculate: process.env.NEXT_PUBLIC_API_ROUTES_RECALCULATE || "/routing/recalculate",
    routesStatus: process.env.NEXT_PUBLIC_API_ROUTES_STATUS || "/routing/set-status",
    routesList: process.env.NEXT_PUBLIC_API_ROUTES_LIST || "/routing/list",
    dispatchPreview: process.env.NEXT_PUBLIC_API_DISPATCH_PREVIEW || "/dispatch/preview",
    dispatchReserve: process.env.NEXT_PUBLIC_API_DISPATCH_RESERVE || "/dispatch/reserve",
    dispatchConfirm: process.env.NEXT_PUBLIC_API_DISPATCH_CONFIRM || "/dispatch/confirm",
    dispatchAuto: process.env.NEXT_PUBLIC_API_DISPATCH_AUTO || "/dispatch/auto",
    dispatchGet: process.env.NEXT_PUBLIC_API_DISPATCH_GET || "/dispatch/get",
    dispatchList: process.env.NEXT_PUBLIC_API_DISPATCH_LIST || "/dispatch/list",
    dispatchCancel: process.env.NEXT_PUBLIC_API_DISPATCH_CANCEL || "/dispatch/cancel",
    analyticsOverview: process.env.NEXT_PUBLIC_API_ANALYTICS_OVERVIEW || "/analytics/tickets/overview",
    analyticsSlaSummary: process.env.NEXT_PUBLIC_API_ANALYTICS_SLA_SUMMARY || "/analytics/sla/summary",
    analyticsBreakdown: process.env.NEXT_PUBLIC_API_ANALYTICS_BREAKDOWN || "/analytics/tickets/breakdown",
    analyticsDaily: process.env.NEXT_PUBLIC_API_ANALYTICS_DAILY || "/analytics/tickets/daily",
    slaList: process.env.NEXT_PUBLIC_API_SLA_LIST || "/sla/tickets/list",
    slaTicketGet: process.env.NEXT_PUBLIC_API_SLA_TICKET_GET || "/sla/tickets/get",
    slaHistory: process.env.NEXT_PUBLIC_API_SLA_HISTORY || "/sla/history/list",
    slaRulesCreate: process.env.NEXT_PUBLIC_API_SLA_RULES_CREATE || "/sla/rules/create",
    slaRulesUpdate: process.env.NEXT_PUBLIC_API_SLA_RULES_UPDATE || "/sla/rules/update",
    slaRulesDelete: process.env.NEXT_PUBLIC_API_SLA_RULES_DELETE || "/sla/rules/delete",
    slaRulesGet: process.env.NEXT_PUBLIC_API_SLA_RULES_GET || "/sla/rules/get",
    slaRulesList: process.env.NEXT_PUBLIC_API_SLA_RULES_LIST || "/sla/rules/list",
    notifications: process.env.NEXT_PUBLIC_API_NOTIFICATIONS_LIST || "/notifications/list",
    notificationsRead: process.env.NEXT_PUBLIC_API_NOTIFICATIONS_READ || "/notifications/read",
    notificationsReadAll: process.env.NEXT_PUBLIC_API_NOTIFICATIONS_READ_ALL || "/notifications/read-all",
    notificationPreferencesGet: process.env.NEXT_PUBLIC_API_NOTIFICATION_PREFERENCES_GET || "/notifications/preferences/get",
    notificationPreferencesUpdate: process.env.NEXT_PUBLIC_API_NOTIFICATION_PREFERENCES_UPDATE || "/notifications/preferences/update",
    notificationDevicesRegister: process.env.NEXT_PUBLIC_API_NOTIFICATION_DEVICES_REGISTER || "/notifications/devices/register",
    notificationDevicesDelete: process.env.NEXT_PUBLIC_API_NOTIFICATION_DEVICES_DELETE || "/notifications/devices/delete",
    notificationTemplatesUpsert: process.env.NEXT_PUBLIC_API_NOTIFICATION_TEMPLATES_UPSERT || "/notifications/templates/upsert",
    notificationTemplatesList: process.env.NEXT_PUBLIC_API_NOTIFICATION_TEMPLATES_LIST || "/notifications/templates/list",
    notificationDeliveriesList: process.env.NEXT_PUBLIC_API_NOTIFICATION_DELIVERIES_LIST || "/notifications/deliveries/list",
    audit: process.env.NEXT_PUBLIC_API_AUDIT_LIST || "/audit/list",
    auditGet: process.env.NEXT_PUBLIC_API_AUDIT_GET || "/audit/get",
    reportsCreate: process.env.NEXT_PUBLIC_API_REPORTS_CREATE || "/reports/create",
    reportsList: process.env.NEXT_PUBLIC_API_REPORTS_LIST || "/reports/list",
    reportsDownload: process.env.NEXT_PUBLIC_API_REPORTS_DOWNLOAD || "/reports/download-url",
    reportsRetry: process.env.NEXT_PUBLIC_API_REPORTS_RETRY || "/reports/retry",
    reportsCancel: process.env.NEXT_PUBLIC_API_REPORTS_CANCEL || "/reports/cancel",
    ticketCategoriesList: process.env.NEXT_PUBLIC_API_TICKET_CATEGORIES_LIST || "/ticket-categories/list",
    ticketCategoriesCreate: process.env.NEXT_PUBLIC_API_TICKET_CATEGORIES_CREATE || "/ticket-categories/create",
    ticketCategoriesGet: process.env.NEXT_PUBLIC_API_TICKET_CATEGORIES_GET || "/ticket-categories/get",
    ticketCategoriesUpdate: process.env.NEXT_PUBLIC_API_TICKET_CATEGORIES_UPDATE || "/ticket-categories/update",
    ticketCategoriesDelete: process.env.NEXT_PUBLIC_API_TICKET_CATEGORIES_DELETE || "/ticket-categories/delete",
    userProfilesUpdate: process.env.NEXT_PUBLIC_API_USER_PROFILES_UPDATE || "/user-profiles/update",
    workProfileByUser: process.env.NEXT_PUBLIC_API_WORK_PROFILE_BY_USER || "/work-profiles/get-by-user",
    workingDepartment: process.env.NEXT_PUBLIC_API_WORKING_DEPARTMENT || "/profile-checks/resolve-working-department",
    workProfilesList: process.env.NEXT_PUBLIC_API_WORK_PROFILES_LIST || "/work-profiles/list",
    workProfilesUpdate: process.env.NEXT_PUBLIC_API_WORK_PROFILES_UPDATE || "/work-profiles/update",
    workProfilesStatus: process.env.NEXT_PUBLIC_API_WORK_PROFILES_STATUS || "/work-profiles/set-status",
    workProfilesChangeDepartment: process.env.NEXT_PUBLIC_API_WORK_PROFILES_CHANGE_DEPARTMENT || "/work-profiles/change-department",
    workProfilesGet: process.env.NEXT_PUBLIC_API_WORK_PROFILES_GET || "/work-profiles/get",
    workProfilesDeactivate: process.env.NEXT_PUBLIC_API_WORK_PROFILES_DEACTIVATE || "/work-profiles/deactivate",
    workProfilesHistory: process.env.NEXT_PUBLIC_API_WORK_PROFILES_HISTORY || "/work-profiles/status-history",
    brigadeMembersList: process.env.NEXT_PUBLIC_API_BRIGADE_MEMBERS_LIST || "/brigade-members/list",
    brigadeSchedulesSet: process.env.NEXT_PUBLIC_API_BRIGADE_SCHEDULES_SET || "/brigade-schedules/set",
    brigadeSchedulesList: process.env.NEXT_PUBLIC_API_BRIGADE_SCHEDULES_LIST || "/brigade-schedules/list",
    assetsCreate: process.env.NEXT_PUBLIC_API_ASSETS_CREATE || "/assets/create",
    assetsGet: process.env.NEXT_PUBLIC_API_ASSETS_GET || "/assets/get",
    assetsUpdate: process.env.NEXT_PUBLIC_API_ASSETS_UPDATE || "/assets/update",
    assetsList: process.env.NEXT_PUBLIC_API_ASSETS_LIST || "/assets/list",
    assetsStatus: process.env.NEXT_PUBLIC_API_ASSETS_STATUS || "/assets/status",
    assetsNearby: process.env.NEXT_PUBLIC_API_ASSETS_NEARBY || "/assets/nearby",
    assetsIncident: process.env.NEXT_PUBLIC_API_ASSETS_INCIDENT || "/assets/incidents",
    assetsRepair: process.env.NEXT_PUBLIC_API_ASSETS_REPAIR || "/assets/repairs",
    assetsInspection: process.env.NEXT_PUBLIC_API_ASSETS_INSPECTION || "/assets/inspections",
    assetsPrediction: process.env.NEXT_PUBLIC_API_ASSETS_PREDICTION || "/assets/prediction",
    assetsMaintenanceCreate: process.env.NEXT_PUBLIC_API_ASSETS_MAINTENANCE_CREATE || "/assets/maintenance/create",
    assetsMaintenanceDue: process.env.NEXT_PUBLIC_API_ASSETS_MAINTENANCE_DUE || "/assets/maintenance/due",
    assetsRisksRecalculate: process.env.NEXT_PUBLIC_API_ASSETS_RISKS_RECALCULATE || "/assets/risks/recalculate",
    analyticsAssetsSummary: process.env.NEXT_PUBLIC_API_ANALYTICS_ASSETS_SUMMARY || "/analytics/assets/summary",
    skillsCreate: process.env.NEXT_PUBLIC_API_SKILLS_CREATE || "/skills/create",
    skillsUpdate: process.env.NEXT_PUBLIC_API_SKILLS_UPDATE || "/skills/update",
    skillsDeactivate: process.env.NEXT_PUBLIC_API_SKILLS_DEACTIVATE || "/skills/deactivate",
    skillsList: process.env.NEXT_PUBLIC_API_SKILLS_LIST || "/skills/list",
    brigadeSkillsAdd: process.env.NEXT_PUBLIC_API_BRIGADE_SKILLS_ADD || "/brigade-skills/add",
    brigadeSkillsRemove: process.env.NEXT_PUBLIC_API_BRIGADE_SKILLS_REMOVE || "/brigade-skills/remove",
    brigadeSkillsList: process.env.NEXT_PUBLIC_API_BRIGADE_SKILLS_LIST || "/brigade-skills/list",
    certificationTypesCreate: process.env.NEXT_PUBLIC_API_CERTIFICATION_TYPES_CREATE || "/certification-types/create",
    certificationTypesUpdate: process.env.NEXT_PUBLIC_API_CERTIFICATION_TYPES_UPDATE || "/certification-types/update",
    certificationTypesList: process.env.NEXT_PUBLIC_API_CERTIFICATION_TYPES_LIST || "/certification-types/list",
    certificationTypeSkillsAdd: process.env.NEXT_PUBLIC_API_CERTIFICATION_TYPE_SKILLS_ADD || "/certification-type-skills/add",
    certificationTypeSkillsRemove: process.env.NEXT_PUBLIC_API_CERTIFICATION_TYPE_SKILLS_REMOVE || "/certification-type-skills/remove",
    certificationTypeSkillsList: process.env.NEXT_PUBLIC_API_CERTIFICATION_TYPE_SKILLS_LIST || "/certification-type-skills/list",
    workProfileCertificationsUpload: process.env.NEXT_PUBLIC_API_WORK_PROFILE_CERTIFICATIONS_UPLOAD || "/work-profile-certifications/upload",
    workProfileCertificationsVerify: process.env.NEXT_PUBLIC_API_WORK_PROFILE_CERTIFICATIONS_VERIFY || "/work-profile-certifications/verify",
    workProfileCertificationsReject: process.env.NEXT_PUBLIC_API_WORK_PROFILE_CERTIFICATIONS_REJECT || "/work-profile-certifications/reject",
    workProfileCertificationsRevoke: process.env.NEXT_PUBLIC_API_WORK_PROFILE_CERTIFICATIONS_REVOKE || "/work-profile-certifications/revoke",
    workProfileCertificationsExpire: process.env.NEXT_PUBLIC_API_WORK_PROFILE_CERTIFICATIONS_EXPIRE || "/work-profile-certifications/expire",
    workProfileCertificationsList: process.env.NEXT_PUBLIC_API_WORK_PROFILE_CERTIFICATIONS_LIST || "/work-profile-certifications/list",
    workProfileSkillsGrant: process.env.NEXT_PUBLIC_API_WORK_PROFILE_SKILLS_GRANT || "/work-profile-skills/grant-manual",
    workProfileSkillsRevoke: process.env.NEXT_PUBLIC_API_WORK_PROFILE_SKILLS_REVOKE || "/work-profile-skills/revoke",
    workProfileSkillsList: process.env.NEXT_PUBLIC_API_WORK_PROFILE_SKILLS_LIST || "/work-profile-skills/list-effective",
    workProfileSkillsBatch: process.env.NEXT_PUBLIC_API_WORK_PROFILE_SKILLS_BATCH || "/work-profile-skills/batch-list-effective",
    workProfileSkillsCheck: process.env.NEXT_PUBLIC_API_WORK_PROFILE_SKILLS_CHECK || "/work-profile-skills/has-skills",
    geoZonesCreate: process.env.NEXT_PUBLIC_API_GEO_ZONES_CREATE || "/geo-zones/create",
    geoZonesUpdate: process.env.NEXT_PUBLIC_API_GEO_ZONES_UPDATE || "/geo-zones/update",
    geoZonesDelete: process.env.NEXT_PUBLIC_API_GEO_ZONES_DELETE || "/geo-zones/delete",
    geoZonesList: process.env.NEXT_PUBLIC_API_GEO_ZONES_LIST || "/geo-zones/list",
    geoZonesCheck: process.env.NEXT_PUBLIC_API_GEO_ZONES_CHECK || "/geo-zones/check-point",
  },
};

const SESSION_KEY = "city-services-session";

export function loadSession(): Session | null {
  if (typeof window === "undefined") return null;
  try { return JSON.parse(sessionStorage.getItem(SESSION_KEY) || "null"); } catch { return null; }
}

export function saveSession(session: Session | null) {
  if (typeof window === "undefined") return;
  if (session) sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
  else sessionStorage.removeItem(SESSION_KEY);
}

type ApiErrorPayload = { error?: string; code?: string };

const errorMessagesByCode: Record<string, string> = {
  INVALID_ARGUMENT: "Проверьте введённые данные",
  UNAUTHENTICATED: "Необходимо войти в систему заново",
  PERMISSION_DENIED: "Недостаточно прав для выполнения действия",
  NOT_FOUND: "Запрошенные данные не найдены",
  ALREADY_EXISTS: "Такая запись уже существует",
  INVALID_STATE: "Действие невозможно в текущем состоянии",
  UPSTREAM_TIMEOUT: "Сервис не успел ответить. Попробуйте ещё раз",
  SERVICE_UNAVAILABLE: "Сервис временно недоступен",
  INTERNAL_ERROR: "Произошла внутренняя ошибка. Попробуйте позже",
};

function userErrorMessage(status: number, payload: ApiErrorPayload, path: string): string {
  if (status === 401) return path === config.endpoints.login ? "Неверная электронная почта или пароль" : "Сессия истекла. Войдите снова";
  if (payload.code && errorMessagesByCode[payload.code]) return errorMessagesByCode[payload.code];
  if (status === 400 || status === 422) return "Проверьте введённые данные";
  if (status === 403) return "Недостаточно прав для выполнения действия";
  if (status === 404) return "Запрошенные данные не найдены";
  if (status === 409) return "Действие невозможно в текущем состоянии";
  if (status === 413) return "Файл слишком большой";
  if (status === 429) return "Слишком много запросов. Повторите попытку позже";
  if (status === 502 || status === 503) return "Сервис временно недоступен";
  if (status === 504) return "Сервис не успел ответить. Попробуйте ещё раз";
  return "Не удалось выполнить запрос. Попробуйте позже";
}

export async function api<T>(path: string, body?: unknown, method = "POST", token?: string): Promise<T> {
  const stored = loadSession();
  let effectiveToken = token && stored?.accessToken && token !== "demo" ? stored.accessToken : token;
  let response = await fetch(`${config.apiBase}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(effectiveToken ? { Authorization: `Bearer ${effectiveToken}` } : {}),
    },
    body: method === "GET" ? undefined : JSON.stringify(body ?? {}),
  });
  if (response.status === 401 && stored?.refreshToken && path !== config.endpoints.refresh) {
    const refreshed = await fetch(`${config.apiBase}${config.endpoints.refresh}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: stored.refreshToken, client_id: "city-web" }),
    });
    if (refreshed.ok) {
      const next = await refreshed.json() as {access_token:string;refresh_token:string;access_expires_at_unix:number};
      saveSession({ ...stored, accessToken: next.access_token, refreshToken: next.refresh_token, expiresAt: next.access_expires_at_unix });
      effectiveToken = next.access_token;
      response = await fetch(`${config.apiBase}${path}`, {
        method,
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${effectiveToken}` },
        body: method === "GET" ? undefined : JSON.stringify(body ?? {}),
      });
    }
  }
  const payload = await response.json().catch(() => ({})) as ApiErrorPayload;
  if (!response.ok) throw new Error(userErrorMessage(response.status, payload, path));
  return payload as T;
}

export function normalizeRole(roles: string[] = []): Role {
  const normalized = roles.map((role) => role.toLowerCase());
  if (normalized.includes("admin")) return "admin";
  if (normalized.includes("dispatcher")) return "dispatcher";
  if (normalized.some((role) => ["worker", "brigade", "employee"].includes(role))) return "worker";
  return "user";
}
