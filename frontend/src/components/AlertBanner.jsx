import { AnimatePresence, motion } from "framer-motion";

export default function AlertBanner({ alert, onDismiss }) {
  return (
    <AnimatePresence>
      {alert && (
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -20 }}
          className="bg-red-500/10 border border-red-500/40 text-red-300 rounded-lg px-4 py-3 mb-4 flex items-center justify-between text-sm"
        >
          <span>⚠ {alert.title} — {alert.message}</span>
          <button
            onClick={onDismiss}
            className="text-red-400 hover:text-red-200 text-xs ml-4"
          >
            dismiss
          </button>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
