/** Moduł w ramce HUD: hairline, narożniki, literowy znacznik (A–D) w odwróconym kolorze. */
export default function Frame({ tag, id, title, meta, actions, className = "", children }) {
  return (
    <section className={`mod ${className}`} aria-labelledby={`${id}-h`}>
      <span className="mod-tag" aria-hidden="true">{tag}</span>
      <header className="mod-head">
        <h2 className="mod-title" id={`${id}-h`}>{title}</h2>
        {meta && <span className="mod-meta">{meta}</span>}
        {actions && <div className="mod-actions">{actions}</div>}
      </header>
      {children}
    </section>
  );
}
