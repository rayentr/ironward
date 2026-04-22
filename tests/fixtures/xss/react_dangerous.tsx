// React dangerouslySetInnerHTML with untrusted content — XSS.

import React from "react";

export function CommentBody({ comment }: { comment: { author: string; body: string } }) {
  return (
    <article>
      <h3>{comment.author}</h3>
      <div dangerouslySetInnerHTML={{ __html: comment.body }} />
    </article>
  );
}
