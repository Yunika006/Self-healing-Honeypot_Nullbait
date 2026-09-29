import axios from "axios";

const API_BASE = process.env.REACT_APP_API_URL || "http://localhost:8000";

const client = axios.create({
  baseURL: API_BASE,
  timeout: 8000,
});

client.interceptors.request.use((config) => {
  const token = localStorage.getItem("nullbait_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const login = (username, password) =>
  client.post("/api/auth/login", { username, password }).then((r) => r.data);

export const fetchSummary = () => client.get("/api/stats/summary").then(r => r.data);
export const fetchByService = () => client.get("/api/stats/by-service").then(r => r.data);
export const fetchTopAttackers = () => client.get("/api/stats/top-attackers").then(r => r.data);
export const fetchAttacks = (limit = 50) => client.get(`/api/attacks?limit=${limit}`).then(r => r.data);
export const fetchServices = () => client.get("/api/services").then(r => r.data);
export const fetchAlerts = () => client.get("/api/alerts").then(r => r.data);
