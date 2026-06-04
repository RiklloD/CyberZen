import type { FunctionReturnType } from "convex/server";
import { useState } from "react";
import { useMutation, useQuery } from "convex/react";
import { MessageSquare, Plus, Trash2, User } from "lucide-react";
import { api } from "../../lib/convex";
import { formatTimestamp } from "../../lib/utils";

type Note = NonNullable<
  FunctionReturnType<typeof api.neuralMemory.getNotes>
>[number];

export default function MemoryNotesSection({
  targetId,
  targetType,
  repositoryId,
}: {
  targetId: string;
  targetType: "pattern" | "prediction" | "episode";
  repositoryId: string;
}) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [newNoteText, setNewNoteText] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const notes = useQuery(api.neuralMemory.getNotes, {
    targetId,
    targetType,
    repositoryId,
  });

  const addNote = useMutation(api.neuralMemory.addNote);
  const deleteNote = useMutation(api.neuralMemory.deleteNote);

  const handleAddNote = async () => {
    if (!newNoteText.trim()) return;

    setIsSubmitting(true);
    try {
      await addNote({
        targetId,
        targetType,
        repositoryId,
        text: newNoteText.trim(),
      });
      setNewNoteText("");
    } catch (error) {
      console.error("Failed to add note:", error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteNote = async (noteId: string) => {
    try {
      await deleteNote({ noteId });
    } catch (error) {
      console.error("Failed to delete note:", error);
    }
  };

  const notesCount = notes?.length || 0;

  return (
    <div className="card card-sm">
      <button
        type="button"
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full flex items-center justify-between text-left"
      >
        <div className="flex items-center gap-2">
          <MessageSquare className="w-4 h-4 text-[var(--sea-blue)]" />
          <p className="panel-label">
            Notes {notesCount > 0 && `(${notesCount})`}
          </p>
        </div>
        <span className="text-xs text-[var(--sea-ink-soft)]">
          {isExpanded ? "Collapse" : "Expand"}
        </span>
      </button>

      {isExpanded && (
        <div className="mt-4 space-y-4">
          {/* Add new note */}
          <div className="space-y-2">
            <textarea
              value={newNoteText}
              onChange={(e) => setNewNoteText(e.target.value)}
              placeholder="Add a note..."
              className="w-full p-2 text-sm bg-[rgba(130,122,110,0.05)] border border-[rgba(130,122,110,0.2)] rounded resize-none focus:outline-none focus:border-[var(--sea-blue)]"
              rows={3}
            />
            <button
              type="button"
              onClick={handleAddNote}
              disabled={!newNoteText.trim() || isSubmitting}
              className="flex items-center gap-2 px-3 py-1.5 bg-[var(--sea-blue)] text-white text-sm rounded hover:bg-[var(--sea-blue-dark)] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Plus className="w-3 h-3" />
              {isSubmitting ? "Adding..." : "Add Note"}
            </button>
          </div>

          {/* Existing notes */}
          {notes && notes.length > 0 && (
            <div className="space-y-3 border-t border-[rgba(130,122,110,0.1)] pt-4">
              {notes.map((note: Note) => (
                <div
                  key={note._id}
                  className="p-3 bg-[rgba(130,122,110,0.03)] rounded border-l-2 border-[var(--sea-blue)]"
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2 text-xs text-[var(--sea-ink-soft)]">
                      <User className="w-3 h-3" />
                      <span>{note.authorName}</span>
                      <span>•</span>
                      <span>{formatTimestamp(note.createdAt)}</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleDeleteNote(note._id)}
                      className="p-1 hover:bg-[rgba(130,122,110,0.1)] rounded"
                      title="Delete note"
                    >
                      <Trash2 className="w-3 h-3 text-[var(--sea-ink-soft)]" />
                    </button>
                  </div>
                  <p className="text-sm whitespace-pre-wrap">{note.text}</p>
                </div>
              ))}
            </div>
          )}

          {notes && notes.length === 0 && (
            <p className="text-sm text-[var(--sea-ink-soft)] italic text-center py-4">
              No notes yet. Add the first note above.
            </p>
          )}
        </div>
      )}
    </div>
  );
}