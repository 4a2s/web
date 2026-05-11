export const GET = () => {
  return new Response(
    JSON.stringify({
      subject: 'acct:antoine@4a2s.ch',
      links: [
        {
          rel: 'http://openid.net/specs/connect/1.0/issuer',
          href: 'https://4a2s.ch',
        },
      ],
    }),
    {
      headers: {
        'Content-Type': 'application/jrd+json; charset=utf-8',
      },
    },
  );
};
