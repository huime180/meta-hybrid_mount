export interface InfoTabContributor {
  login: string;
  avatar_url: string;
  html_url: string;
  type: string;
  url: string;
  name: string;
  bio: string;
}

export interface InfoTabSection {
  id: string;
  label: string;
  repoDisplayName: string;
  repoUrl: string;
  contributors: InfoTabContributor[];
}
