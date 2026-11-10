"use client";

import { Ticket } from "./api";

import { statusNames } from "./city-shared";

export function TicketCards({
  tickets,
  selected,
  onSelect,
}: {
  tickets: Ticket[];
  selected?: string;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="ticket-list">
      {tickets.slice(0, 6).map((ticket) => (
        <button
          key={ticket.id}
          className={selected === ticket.id ? "selected" : ""}
          onClick={() => onSelect(ticket.id)}
        >
          <span className={`priority ${ticket.priority.toLowerCase()}`} />
          <div>
            <b>{ticket.title}</b>
            <em className={`status ${ticket.status.toLowerCase()}`}>
              {statusNames[ticket.status] || ticket.status}
            </em>
          </div>
        </button>
      ))}
    </div>
  );
}
