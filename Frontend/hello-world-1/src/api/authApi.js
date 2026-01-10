const USER_BASE = "http://localhost:8081";   // user-service
const PROFILE_BASE = "http://localhost:8081"; // profile-service

export async function register({ email, password, role, firstName, lastName }) {
  // 1) Create user in user-service
  const userRes = await fetch(`${USER_BASE}/users/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, role }), 
  });

  const userData = await userRes.json().catch(() => null);

  if (!userRes.ok || !userData) {
    throw new Error(
      (userData && userData.message) || "User registration failed"
    );
  }

  // userData is e.g. { id, role }
  const userId = userData.id;

  // 2) Create profile in profile-service
  let profileUrl;
  if (role === "PATIENT") {
    profileUrl = `${PROFILE_BASE}/patients/register`;
  } else if (role === "DOCTOR" || role === "STAFF") {
    profileUrl = `${PROFILE_BASE}/practitioners/register`;
  } else {
    throw new Error("Unknown role");
  }

  const profileRes = await fetch(profileUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({firstName, lastName, userId}),
  });

  const profileData = await profileRes.json().catch(() => null);

  if (!profileRes.ok || !profileData) {
    throw new Error(
      (profileData && profileData.message) || "Profile creation failed"
    );
  }

  // 3) Return both, or just userData if that’s all you need
  return { user: userData, profile: profileData };
}

export async function login({ email, password }) {
  const res = await fetch(`${USER_BASE}/users/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) throw new Error(await res.text().catch(() => "Login failed"));
  return res.json();             // expect a user object back
}