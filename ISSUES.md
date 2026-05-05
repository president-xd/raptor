APT Library is loading successfully in the browser. I verified the page renders a full profile grid, the region filter (Russia) narrows results, clicking a card opens the actor modal with full TTP list, and Refresh Profiles reloads the data.

Where the APT Library lives

UI + modal: Dashboard.jsx:1748-1836
Client fetch: raptorApi.js:140-143 and Dashboard.jsx:281-300
Backend endpoint: main.py:2338-2353
Profile loader + summaries: apt_profiles.py:14-145
Response model: models.py:268-285
Issues / improvements

Potential latency on every request: get_apt_profiles calls load_apt_profiles() each time, which parses the STIX bundle per request. Consider caching the computed profiles in memory with a simple TTL or a file mtime guard. main.py:2338-2353, apt_profiles.py:14-145
Payload size is larger than needed for the list view: the API returns full techniques arrays for every profile. That’s heavy for the list grid where only counts are shown. A ?include_techniques=false default or a separate detail endpoint would reduce payload and render time. models.py:268-285, Dashboard.jsx:1748-1820
Auth UX gap: on 401, loadAptProfiles only sets an error and doesn’t open the auth dialog like other loaders do. This can leave users stuck if auth is required. Dashboard.jsx:281-300
Stale modal after refresh: refreshing profiles doesn’t clear selectedActor, so if the data changes, the open modal can show stale details. Resetting selectedActor on refresh would avoid that. Dashboard.jsx:1748-1836