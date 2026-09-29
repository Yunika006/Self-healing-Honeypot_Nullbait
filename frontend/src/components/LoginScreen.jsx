import { useState } from "react";
import { login } from "../utils/api";

export default function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    try {
      const data = await login(username, password);
      localStorage.setItem("nullbait_token", data.access_token);
      onLogin();
    } catch (err) {
      setError("Invalid credentials");
    }
  };

  return (
    <div className="min-h-screen bg-nullbg flex items-center justify-center">
      <form
        onSubmit={handleSubmit}
        className="bg-nullcard border border-nullborder rounded-lg p-8 w-80"
      >
        <h1 className="text-xl font-bold text-white mb-1">NullBait</h1>
        <p className="text-gray-500 text-sm mb-6">Dashboard sign in</p>

        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="w-full mb-3 px-3 py-2 rounded bg-nullbg border border-nullborder text-white text-sm"
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full mb-4 px-3 py-2 rounded bg-nullbg border border-nullborder text-white text-sm"
        />
        {error && <p className="text-red-400 text-xs mb-3">{error}</p>}
        <button
          type="submit"
          className="w-full bg-nullaccent text-white rounded py-2 text-sm font-medium"
        >
          Sign in
        </button>
      </form>
    </div>
  );
}
