cmd_/home/null/shared/icebreaker/cr0_write_test/Module.symvers := sed 's/\.ko$$/\.o/' /home/null/shared/icebreaker/cr0_write_test/modules.order | scripts/mod/modpost -m -a  -o /home/null/shared/icebreaker/cr0_write_test/Module.symvers -e -i Module.symvers   -T -