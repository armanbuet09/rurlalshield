import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import { IConstruct } from 'constructs';

/** Materialize CDK grant documents as customer-managed policies before audit checks. */
export class ManagedRolePolicies implements cdk.IAspect {
  public visit(node: IConstruct): void {
    if (!(node instanceof iam.Policy)) return;
    const original = node.node.defaultChild;
    if (!(original instanceof iam.CfnPolicy) || node.document.isEmpty) return;

    // Keep the same construct path/logical ID so grant dependencies still refer
    // to the policy attachment. Document and attachment lists remain lazy: grants
    // added later in synthesis are preserved, without changing any permissions.
    const logicalId = original.logicalId;
    node.node.tryRemoveChild(original.node.id);
    const managed = new iam.CfnManagedPolicy(node, original.node.id, {
      policyDocument: original.policyDocument,
      roles: original.roles,
      users: original.users,
      groups: original.groups,
    });
    managed.overrideLogicalId(logicalId);
    Object.assign(managed.cfnOptions, original.cfnOptions);
    managed.node.addDependency(...original.node.dependencies);
    node.node.defaultChild = managed;
  }
}
