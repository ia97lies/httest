;; $Header: /cvsroot/htt/httest/plugins/xemacs/htt.el,v 1.2 2008/02/08 08:31:07 pbuchbinder Exp $
;; htt is available at http://sourceforge.net/projects/httest

(defvar htt-mode-map
  (let ((map (make-sparse-keymap)))
    map)
)

(defvar htt-mode-syntax-table nil
  "syntax table used in htt mode")
(setq htt-mode-syntax-table (make-syntax-table))
(modify-syntax-entry ?# "<\n" htt-mode-syntax-table)
(modify-syntax-entry ?\n ">#" htt-mode-syntax-table)

(defvar htt-font-lock-keywords
  (list
   (list "\\(\\$[a-zA-Z0-9_]+\\)"		 1 'font-lock-type-face)
   (list "\\(\\${[a-zA-Z0-9_]+}\\)"		 1 'font-lock-type-face)
   
   ;; global, outside CLIENT/SERVER
   (list
    (concat "^[ \t]*\\(\\<"
            (mapconcat 'identity
                       '(
                         "INCLUDE"
                         "CLIENT"
                         "SERVER"
                         "EXEC"
                         "SET"
                         "END"
                         "GO"
                         "TIMEOUT"
                         "BLOCK"
                         )
                       "\\>\\|\\<")
            "\\>\\)") 1 'bold)
   ;; local inside CLIENT/SERVER
   (list
    (concat "\\(\\<"
            (mapconcat 'identity
                        '(
                          ;; alphabetical oder!
                          "_CALL"
                          "_CLOSE"
                          "_CHUNK"
                          "_DEBUG"
                          "_DOWN"
                          "_END"
                          "_EXEC"
                          "_EXIT"
                          "_EXPECT"
                          "_FLUSH"
                          "_HEADER"
                          "_IF"
                          "_IGNORE_ERR"
                          "_LOG_LEVEL"
                          "_LOOP"
                          "_MATCH"
                          "_PIPE"
                          "_RAND"
                          "_REQ"
                          "_RES"
                          "_SEND"
                          "_SET"
                          "_SLEEP"
                          "_SOCKSTATE"
                          "_TIME"
                          "_TIMEOUT"
                          "_UP"
                          "_WAIT"
                          )
                        "\\>\\|\\<")
             "\\>\\)") 1 'font-lock-reference-face)
    (list
     (concat "\\(\\<"
             (mapconcat 'identity
                 '(
                   "__GET "
                   "__POST "
                  )
                 "\\>\\|\\<")
             "\\>\\)") 1 'font-lock-type-face)

    )


  "Keywords to highlight in HTT mode")


(defun htt-mode ()
  "Major mode for editing htt (HTTP Test Tool) files.

  \\{htt-mode-map}"

  (interactive)
  (kill-all-local-variables)
  (use-local-map htt-mode-map)

  (setq major-mode 'htt-mode)
  (setq mode-name "htt")
  (set-syntax-table htt-mode-syntax-table)
  (make-local-variable 'font-lock-defaults)
  (setq font-lock-defaults '(htt-font-lock-keywords nil nil ((?@ . "w")) nil) )
  (font-lock-mode)
  (font-lock-fontify-buffer)
  (setq paragraph-start "[#@ ]")
  (setq paragraph-separate "[#@ ]")
  (auto-fill-mode -1)
  (run-hooks 'htt-mode-hook))

(provide 'htt-mode)


;;
;; When to use the htt-mode:
;;
(add-to-list 'auto-mode-alist '(".*\.htt$" . htt-mode))
(autoload 'htt-mode "htt" "HTT editing mode" t)
