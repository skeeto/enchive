;;; enchive-mode.el --- automatic encrypt/decrypt -*- lexical-binding: t; -*-

;; This is free and unencumbered software released into the public domain.

;;; Commentary:

;; Load this file, then M-x `enchive-mode' (global minor mode) to
;; enable automatic encryption and decryption of Enchive files.

;;; Code:

(defgroup enchive ()
  "Interface to Enchive subprocess."
  :group 'data)

(defcustom enchive-program-name "enchive"
  "Path to the locally installed enchive binary.")

(defvar enchive-handler-entry (cons "\\.enchive\\'" #'enchive-file-handler)
  "Entry for `enchive-mode' in `file-name-handler-alist'.")

(defvar enchive-auto-mode-entry (list "\\.enchive\\'" nil 'enchive)
  "Entry for `enchive-mode' in `auto-mode-alist'.")

(defun enchive-file-handler (operation &rest args)
  "Handler for `file-name-handler-alist' for automatic encrypt/decrypt."
  (let ((file-name-handler-alist ()))
    (cond ((eq operation 'insert-file-contents)
           (let ((file (car args)))
             (unless (= 0 (call-process enchive-program-name file '(t nil) nil
                                        "--pinentry" "--agent" "extract"))
               (error "Enchive subprocess failed"))
             (setf buffer-file-name file)
             (list file (buffer-size))))
          ((eq operation 'write-region)
           (call-process-region (nth 0 args) (nth 1 args)
				enchive-program-name nil nil nil
                                "archive" "/dev/stdin" (nth 2 args)))
          ((apply operation args)))))

;;;###autoload
(define-minor-mode enchive-mode
  "Global minor mode to automatically encrypt/decrypt enchive files."
  :global t
  (setf file-name-handler-alist
        (delq enchive-handler-entry file-name-handler-alist))
  (setf auto-mode-alist
        (delq enchive-auto-mode-entry auto-mode-alist))
  (when enchive-mode
    (setf file-name-handler-alist
          (cons enchive-handler-entry file-name-handler-alist))
    (setf auto-mode-alist
          (cons enchive-auto-mode-entry auto-mode-alist))))

(provide 'enchive-mode)

;;; enchive-mode.el ends here
