# Hyperlight Improvement Proposals (HIPs)

Hyperlight Improvement Proposals, otherwise known as HIPs, are largely influenced by the Kubernetes
Enhancement Proposal (KEP) process which provides a standardized development process for Hyperlight
enhancements. You can read more about the 
[KEP process in 0000-kep-process here](https://github.com/kubernetes/enhancements/blob/master/keps/sig-architecture/0000-kep-process/README.md).

## Authoring a HIP
When you have a new enhancement that is more than a relatively trivial enhancement or bug fix, the
change should be first socialized as a HIP. To help authors to get started a HIP template is located in
[NNNN-hip-template](./NNNN-hip-template/README.md). 

1. Create a new directory under [the proposals directory](../proposals) in the form of `NNNN-hip-${hip_name}`
  where `NNNN` is the next HIP number available. For example, if HIP 0001 is currently the highest number HIP and
  your enhancement is titled "Make Me a Sandwich", then your HIP would be `0002-hip-make-me-a-sandwich`.
2. Within your `NNNN-hip-${hip_name}` directory create a file named `README.md` containing a copy of the HIP
  template.
3. Author the content of the template. Not all sections are necessary. Please consider filling out the
  summary, motivation, and proposal sections first to gather early feedback on the desirability of the
  enhancement through a draft pull request.
4. After socializing the proposal and integrating early feedback, continue with the rest of the sections.
5. Update the pull request with the rest of the sections and remove the draft status from the pull request.
6. Address any feedback to the proposal and get it merged.
7. Implement the enhancement.

